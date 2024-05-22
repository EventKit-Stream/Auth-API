"""api.routes.TWITCH
File: twitch.py
Author: LordLumineer
Date: 2024-05-03

Purpose: This file contains the handlers for the twitch AUTH.
"""

import os
from datetime import datetime, timezone
import requests
from fastapi.responses import HTMLResponse
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from models import FetchedUserInDB, UserInDB
from api.routes.users import get_current_active_user
from core.config import log
from core.twitch import link_to_google, link_to_local, validate_id_token
from core.security import Token, TokenData, create_access_token
from core.db import (
    fetch_twitch_user_by_id,
    save_pfp,
    create_user,
    update_user_by_id,
    fetch_twitch_user_by_email,
)

router = APIRouter()


@router.patch("/callback", response_model=Token)
async def twitch_landing(
    code: str,
    scope: str,
    nonce: str,
    redirect_uri: str,
    background_tasks: BackgroundTasks,
):
    """The Twitch Callback endpoint that the "blank" page calls to authenticate the user.

    Args:
        code (str): Code returned by Twitch
        scope (str): scope returned by Twitch
        nonce (str): String to verify the ID token
        redirect_uri (str): the redirect uri used to authenticate with Twitch
        background_tasks (BackgroundTasks): _description_


    Raises:
        HTTPException: HTTP_409_CONFLICT - if the Google Email is already used.
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the user can't be created.

    Returns:
        Token: {"access_token": str, "token_type": str}
    """

    user_info_data = await validate_id_token(
        scope.split(" "), code, redirect_uri, nonce
    )

    twitch_user = await fetch_twitch_user_by_email(user_info_data["email"])
    if twitch_user and (twitch_user.twitch_id != user_info_data["sub"]):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "Twitch Email already used",
                "error_description": "You can't use two different Twitch accounts with the same email address.",
            },
        )

    if twitch_user := await fetch_twitch_user_by_id(user_info_data["sub"]):
        user_save = twitch_user

        if (
            twitch_user.twitch_username != user_info_data["preferred_username"].lower()
            or twitch_user.full_name != user_info_data["preferred_username"]
        ):
            twitch_user.twitch_username = user_info_data["preferred_username"].lower()
            twitch_user.full_name = user_info_data["preferred_username"]
            if (
                twitch_user.twitch_email_verified != user_info_data["email_verified"]
                or twitch_user.twitch_email != user_info_data["email"]
            ):
                twitch_user.twitch_email_verified = user_info_data["email_verified"]
                twitch_user.twitch_email = user_info_data["email"]
                if google_user_token := await link_to_google(
                    user_info_data, twitch_user
                ):
                    return google_user_token
                if local_user_token := await link_to_local(
                    user_info_data, background_tasks, twitch_user
                ):
                    return local_user_token

            twitch_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
            if updated_user := await update_user_by_id(twitch_user):
                user_save = updated_user
            else:
                log.warning("Failed to update user")

        return await create_access_token(
            subject=TokenData(
                uuid=user_save.uuid,
                login_method=user_save.login_method,
                platform_uuid=user_save.twitch_id,
                username=user_save.twitch_username,
                email=user_save.twitch_email,
            )
        )

    if google_user_token := await link_to_google(user_info_data):
        return google_user_token

    if local_user_token := await link_to_local(user_info_data, background_tasks):
        return local_user_token

    new_twitch_user = UserInDB(
        login_method="twitch",
        full_name=user_info_data["preferred_username"],
        twitch_id=user_info_data["sub"],
        twitch_username=user_info_data["preferred_username"].lower(),
        twitch_email=user_info_data["email"],
        twitch_email_verified=user_info_data["email_verified"],
        updated_at=str(int(datetime.now(timezone.utc).timestamp())),
    )
    get_pfp = requests.get(url=user_info_data["picture"], timeout=10).content
    filename = f"pfp_{new_twitch_user.twitch_username}_{int(datetime.now(timezone.utc).timestamp())}_{os.path.basename(user_info_data["picture"])}"
    new_twitch_user.picture_id = await save_pfp(filename, get_pfp)
    new_user = await create_user(new_twitch_user)
    if not new_user:
        log.warning("Failed to create user")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to create user",
                "error_description": "Failed to create user",
            },
        )
    return await create_access_token(
        subject=TokenData(
            uuid=new_user.uuid,
            login_method=new_user.login_method,
            platform_uuid=new_user.twitch_id,
            username=new_user.twitch_username,
            email=new_user.twitch_email,
        )
    )


@router.get("/callback", response_class=HTMLResponse)
async def twitch_landing_html():
    """The Twitch Callback "blank" page that the user is redirected to after authenticating with Twitch.

    Returns:
        HTML: The HTML content of the page
    """
    html_file = os.path.join("assets/html/twitch-callback.html")
    with open(html_file, "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


@router.post("/scopes", response_model=list[str])
async def post_twitch_scopes(
    scopes: list[str], current_user: FetchedUserInDB = Depends(get_current_active_user)
):
    """Update the Twitch scopes of the user.

    Args:
        scopes (list[str]): List of scopes to add to the user.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        list[str]: List of scopes of the user.
    """
    for scope in scopes:
        if scope not in current_user.twitch_scope:
            current_user.twitch_scope.append(scope)
    updated_user = await update_user_by_id(current_user)
    return updated_user.twitch_scope


@router.delete("/scopes", response_model=list[str])
async def delete_twitch_scopes(
    scopes: list[str], current_user: FetchedUserInDB = Depends(get_current_active_user)
):
    """Delete the Twitch scopes of the user.

    Args:
        scopes (list[str]): List of scopes to remove from the user.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        list[str]: List of scopes of the user.
    """
    for scope in scopes:
        if scope in current_user.twitch_scope:
            current_user.twitch_scope.remove(scope)
    updated_user = await update_user_by_id(current_user)
    return updated_user.twitch_scope


@router.get("/scopes", response_model=list[str])
async def get_twitch_scopes(
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Get the Twitch scopes of the user.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        list[str]: List of scopes of the user.
    """
    return current_user.twitch_scope
