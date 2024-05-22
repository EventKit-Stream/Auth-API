"""core.GOOGLE
File: google.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file functions and the routines related to twitch.
"""

from datetime import datetime, timezone
import requests
from authlib.jose import jwt
from fastapi import BackgroundTasks, HTTPException, status

from models import FetchedUserInDB
from core.db import (
    fetch_local_user_by_email,
    fetch_twitch_user_by_email,
    remove_user_by_id,
    update_user_by_id,
)
from core.config import settings, log
from core.email import send_verification_email
from core.security import TokenData, create_access_token


async def decode_id_token(id_token: str):
    """Decode the Google ID Token and return the Decoded Data and the User Info Endpoint.

    Args:
        id_token (str): The Google ID Token to Decode.

    Returns:
        dict: The Decoded ID Token Data.
    """
    oidc_server = "accounts.google.com"
    oidc_config = requests.get(
        url=f"https://{oidc_server}/.well-known/openid-configuration", timeout=10
    ).json()
    jwks = requests.get(oidc_config["jwks_uri"], timeout=10).json()
    return jwt.decode(id_token, key=jwks), oidc_config["userinfo_endpoint"]


async def validate_id_token(scopes: list, code: str, redirect_uri: str, nonce: str):
    """Validate the ID Token and return the User Info Data.

    Args:
        scopes (list): List of Scopes from Google.
        code (str): Code from Google.
        redirect_uri (str): Redirect URI from Google.
        nonce (str): Nonce to verify the ID Token.

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Missing openid scope or Missing data.
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Google API Error.

    Returns:
        dict: The User Info Data.
    """
    if "openid" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Missing openid scope",
                "error_description": "The openid scope is required to authenticate with Twitch.",
            },
        )
    if "email" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Missing email scope",
                "error_description": "The email scope is required to authenticate with Twitch.",
            },
        )
    if "profile" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Missing profile scope",
                "error_description": "The profile scope is required to authenticate with Twitch.",
            },
        )

    response = requests.post(
        url="https://oauth2.googleapis.com/token",
        params={
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "nonce": nonce,
        },
        timeout=10,
    )
    response_data = response.json()
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Google API Error",
                "error_description": response_data["message"],
            },
        )

    if not response_data["access_token"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Google API Error",
                "error_description": "No access token was returned.",
            },
        )

    decoded_id, userinfo_endpoint = await decode_id_token(response_data["id_token"])

    user_info = requests.get(
        url=userinfo_endpoint,
        headers={"Authorization": f"Bearer {response_data['access_token']}"},
        timeout=10,
    )
    user_info_data = user_info.json()

    try:
        assert (
            decoded_id["aud"] == decoded_id["azp"]
        ), "The ID token AUD and AZP do not match."
        assert (
            decoded_id["iss"] == "https://accounts.google.com"
        ), "The ID token and user info do not match. ISS"
        assert (
            decoded_id["sub"] == user_info_data["sub"]
        ), "The ID token and user info do not match. SUB"
        assert (
            decoded_id["email"] == user_info_data["email"]
        ), "The ID token and user info do not match. EMAIL"
        assert (
            decoded_id["email_verified"] == user_info_data["email_verified"]
        ), "The ID token and user info do not match. EMAIL_VERIFIED"
        assert (
            decoded_id["name"] == user_info_data["name"]
        ), "The ID token and user info do not match. name"
        assert (
            decoded_id["given_name"] == user_info_data["given_name"]
        ), "The ID token and user info do not match. given_name"
        assert (
            decoded_id["family_name"] == user_info_data["family_name"]
        ), "The ID token and user info do not match. family_name"
        assert (
            decoded_id["nonce"] == nonce
        ), "The ID token and user info do not match. NONCE"

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Google API Error",
                "error_description": e,
            },
        ) from e

    return user_info_data


async def link_to_twitch(
    user_info_data: dict, existing_user: FetchedUserInDB | None = None
):
    """Check if the User is already in the Database and Link the Google Account with the Twitch Account.

    Args:
        user_info_data (dict): The User Info Data from Google.
        existing_user (FetchedUserInDB, optional): The Existing User in the Database to remove once the new user is created.

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Twitch Email not verified.

    Returns:
        Token: {"access_token": str, "token_type": str}
    """
    twitch_user = await fetch_twitch_user_by_email(user_info_data["email"])
    if twitch_user:
        if not (twitch_user.twitch_email_verified and user_info_data["email_verified"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Twitch Email not verified",
                    "error_description": "You need to have a verified Twitch and a verified Google email address account to link this account.",
                },
            )
        save_user = twitch_user
        twitch_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
        twitch_user.google_id = user_info_data["sub"]
        twitch_user.google_username = user_info_data["name"].lower().replace(" ", "_")
        twitch_user.google_email = user_info_data["email"]
        twitch_user.google_email_verified = user_info_data["email_verified"]
        updated_user = await update_user_by_id(twitch_user)
        if not updated_user:
            log.warning("Failed to update user")
        else:
            save_user = updated_user
            if existing_user:
                if not await remove_user_by_id(existing_user):
                    log.warning(
                        f"Failed to remove user {existing_user.uuid} after linking Google with Twitch."
                    )
        return await create_access_token(
            subject=TokenData(
                uuid=save_user.uuid,
                login_method=save_user.login_method,
                platform_uuid=save_user.twitch_id,
                username=save_user.twitch_username,
                email=save_user.twitch_email,
            )
        )
    return None


async def link_to_local(
    user_info_data: dict,
    background_tasks: BackgroundTasks,
    existing_user: FetchedUserInDB | None = None,
):
    """Check if the User is already in the Database and Link the Google Account with the Local Account.

    Args:
        user_info_data (dict): Google User Info Data.
        background_tasks (BackgroundTasks): Background Task to Send Verification Email.
        existing_user (FetchedUserInDB, optional): The Existing User in the Database to remove once the new user is created.

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Local Email not verified.

    Returns:
        Token: {"access_token": str, "token_type": str}
    """
    local_user = await fetch_local_user_by_email(user_info_data["email"])
    if local_user:
        if not (local_user.local_email_verified and user_info_data["email_verified"]):
            background_tasks.add_task(send_verification_email, local_user)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Local Email not verified",
                    "error_description": "You need to have a verified Local and a verified Google email address account to link this account.",
                },
            )
        save_user = local_user
        local_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
        local_user.google_id = user_info_data["sub"]
        local_user.google_username = user_info_data["name"].lower().replace(" ", "_")
        local_user.google_email = user_info_data["email"]
        local_user.google_email_verified = user_info_data["email_verified"]
        updated_user = await update_user_by_id(local_user)
        if not updated_user:
            log.warning("Failed to update user")
        else:
            save_user = updated_user
            if existing_user:
                if not await remove_user_by_id(existing_user):
                    log.warning(
                        f"Failed to remove user {existing_user.uuid} after linking Google with Local."
                    )
        return await create_access_token(
            subject=TokenData(
                uuid=save_user.uuid,
                login_method=save_user.login_method,
                platform_uuid=save_user.local_id,
                username=save_user.local_username,
                email=save_user.local_email,
            )
        )
    return None
