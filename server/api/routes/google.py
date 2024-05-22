"""api.routes.GOOGLE
File: google.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the handlers for the google AUTH.
"""

import os
from datetime import datetime, timezone
import requests
from fastapi.responses import HTMLResponse
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from models import FetchedUserInDB, UserInDB
from api.routes.users import get_current_active_user
from core.security import Token, TokenData, create_access_token
from core.config import log
from core.google import (
    link_to_local,
    link_to_twitch,
    validate_id_token,
)
from core.db import (
    fetch_google_user_by_id,
    save_pfp,
    create_user,
    update_user_by_id,
    fetch_google_user_by_email,
)

router = APIRouter()


@router.patch("/callback", response_model=Token)
async def google_landing(
    code: str,
    scope: str,
    nonce: str,
    redirect_uri: str,
    background_tasks: BackgroundTasks,
):
    """The Google Callback endpoint that the "blank" page calls to authenticate the user.

    Args:
        code (str): Code from Google
        scope (str): Scopes from Google
        nonce (str): Nonce to validate the ID token
        redirect_uri (str): The redirect URI
        background_tasks (BackgroundTasks): background_tasks (to be used to send emails, etc.)

    Raises:
        HTTPException: HTTP_409_CONFLICT if the Google Email is already used
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR if the user can't be created

    Returns:
        Token: {"access_token": str, "token_type": str}
    """
    user_info_data = await validate_id_token(
        scope.split(" "), code, redirect_uri, nonce
    )

    google_user = await fetch_google_user_by_email(user_info_data["email"])
    if google_user and (google_user.google_id != user_info_data["sub"]):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "Google Email already used",
                "error_description": "You can't use two different Google accounts with the same email address.",
            },
        )

    if google_user := await fetch_google_user_by_id(user_info_data["sub"]):
        user_save = google_user

        if (
            google_user.google_username
            != user_info_data["name"].lower().replace(" ", "_")
            or google_user.full_name != user_info_data["name"]
        ):
            google_user.google_username = (
                user_info_data["name"].lower().replace(" ", "_")
            )
            google_user.full_name = user_info_data["name"]
            if (
                google_user.twitch_email_verified != user_info_data["email_verified"]
                or google_user.google_email != user_info_data["email"]
            ):
                google_user.google_email = user_info_data["email"]
                google_user.twitch_email_verified = user_info_data["email_verified"]
                if twitch_user_token := await link_to_twitch(
                    user_info_data, google_user
                ):
                    return twitch_user_token
                if local_user_token := await link_to_local(
                    user_info_data, background_tasks, google_user
                ):
                    return local_user_token

            google_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
            if updated_user := await update_user_by_id(google_user):
                user_save = updated_user
            else:
                log.warning("Failed to update user")

        return await create_access_token(
            subject=TokenData(
                uuid=user_save.uuid,
                login_method=user_save.login_method,
                platform_uuid=user_save.google_id,
                username=user_save.google_username,
                email=user_save.google_email,
            )
        )

    if twitch_user_token := await link_to_twitch(user_info_data):
        return twitch_user_token
    if local_user_token := await link_to_local(user_info_data, background_tasks):
        return local_user_token

    new_google_user = UserInDB(
        login_method="google",
        full_name=user_info_data["name"],
        google_id=user_info_data["sub"],
        google_username=user_info_data["name"].lower().replace(" ", "_"),
        google_email=user_info_data["email"],
        google_email_verified=user_info_data["email_verified"],
        updated_at=str(int(datetime.now(timezone.utc).timestamp())),
    )
    get_pfp = requests.get(url=user_info_data["picture"], timeout=10).content
    filename = f"pfp_{new_google_user.google_username}_{
        int(datetime.now(timezone.utc).timestamp())}_{os.path.basename(user_info_data["picture"])}.png"
    new_google_user.picture_id = await save_pfp(filename, get_pfp)
    new_user = await create_user(new_google_user)
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
            platform_uuid=new_user.google_id,
            username=new_user.google_username,
            email=new_user.google_email,
        )
    )


@router.get("/callback", response_class=HTMLResponse)
async def google_landing_html():
    """The Google Callback "blank" page that the user is redirected to after authenticating with Google.

    Returns:
        HTML: The HTML content of the page
    """
    html_file = os.path.join("assets/html/google-callback.html")
    with open(html_file, "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


@router.post("/scopes", response_model=list[str])
async def post_google_scopes(
    scopes: list[str], current_user: FetchedUserInDB = Depends(get_current_active_user)
):
    """Update the Google scopes of the user.

    Args:
        scopes (list[str]): List of scopes to add to the user.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        list[str]: List of scopes of the user.
    """
    for scope in scopes:
        if scope not in current_user.google_scope:
            current_user.google_scope.append(scope)
    updated_user = await update_user_by_id(current_user)
    return updated_user.google_scope


@router.delete("/scopes", response_model=list[str])
async def delete_google_scopes(
    scopes: list[str], current_user: FetchedUserInDB = Depends(get_current_active_user)
):
    """Delete the Google scopes of the user.

    Args:
        scopes (list[str]): List of scopes to remove from the user.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        list[str]: List of scopes of the user.
    """
    for scope in scopes:
        if scope in current_user.google_scope:
            current_user.google_scope.remove(scope)
    updated_user = await update_user_by_id(current_user)
    return updated_user.google_scope


@router.get("/scopes", response_model=list[str])
async def get_google_scopes(
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Get the Google scopes of the user.

    Headers:
        Authorization: Bearer <access_token>

    Returns:
        list[str]: List of scopes of the user.
    """
    return current_user.google_scope
