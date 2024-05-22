"""api.routes.ADMIN
File: admin.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the handlers for the admin routes
(ONLY: the docs deportation are defined in the main.py).
"""

from fastapi.responses import HTMLResponse
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from models import AdminUser
from core.config import settings
from core.db import fetch_admin_user
from core.security import (
    TokenData,
    verify_password,
    decode_access_token,
    Token,
    create_access_token,
)


router = APIRouter()

oauth2_scheme_admin = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_STR}/admin/login",
    scheme_name="admin",
    scopes={"admin": "Admin access"},
    description="Admin access token",
    auto_error=True,
)


async def get_current_admin_user(token: str = Depends(oauth2_scheme_admin)):
    """Get the current admin user from the token.

    Args:
        token (str): An access token (without the Bearer part).

    Raises:
        HTTPException: HTTP_401_UNAUTHORIZED if the token is invalid.

    Returns:
        AdminUser:
                username: str
                hashed_password: str
    """
    try:
        claims = await decode_access_token(token)
        sub: TokenData = claims["sub"]
        user = await fetch_admin_user(sub.username)
        if user is None:
            raise ValueError("User not found")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Could not validate credentials",
                "error_description": f"Invalid token | {str(e)}",
            },
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    return user


async def authenticate_admin_user(username: str, password: str):
    """From a username and password, authenticate an admin user in the database.

    Args:
        username (str): Username of the admin user, used the fetch the user.
        password (str): Password of the admin user, used to verify the password 
            (against the hash saved in the database).

    Raises:
        HTTPException: HTTP_401_UNAUTHORIZED If the username or password is incorrect.

    Returns:
        AdminUser:
                username: str
                hashed_password: str
    """
    user = await fetch_admin_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Incorrect username or password",
                "error_description": "The username provided does not exist in the database. Please check and try again.",
            },
        )
    if not await verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Incorrect username or password",
                "error_description": "The password provided is incorrect. Please check and try again.",
            },
        )
    return user


@router.post("/login", response_model=Token)
async def login_admin_user(form_data: OAuth2PasswordRequestForm = Depends()):
    """Endpoint to login an admin user.

    Args:
        form_data (OAuth2PasswordRequestForm):
                Use ONLY the username and password (they are currently the only fields supported).

    Raises:
        HTTPException: Raise an HTTP_401_UNAUTHORIZED if the username or password is incorrect.

    Returns:
        Token:
                token_type: str,
                access_token: str,
    """
    user = await authenticate_admin_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Incorrect username or password",
                "error_description": "The username or password provided is incorrect.",
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await create_access_token(
        subject=TokenData(
            uuid="this_is_an_admin_user",
            login_method="admin",
            platform_uuid="admin_uuid",
            username=user.username,
            email="this_an_admin",
        ),
        expires_delta=15,
    )


@router.get("/")
async def get_admin_user(user: AdminUser = Depends(get_current_admin_user)):
    """Simple endpoint used to get the current admin user information.

    Headers:
        Authorization: Bearer {token}

    Returns:
        AdminUser:
                username: str,
                hashed_password: str,
    """
    return user


@router.get("/validate-token", status_code=status.HTTP_202_ACCEPTED)
async def validate_admin_token(user: AdminUser = Depends(get_current_admin_user)):
    """Simple endpoint to validate the token.

    Headers:
        Authorization: Bearer {token}

    Returns:
        {"message": "Token is valid"}: 
            Only if it succeeds to validate the token (Ref. get_current_admin_user).
    """
    return {"message": f"Token is valid - {user.username}"}


@router.get("/login", include_in_schema=False)
async def get_login():
    """HTML page to login as an admin.

    Returns:
        HTML: HTMLResponse with the content of the admin login page.
    """
    with open("./assets/html/adminLogin.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
