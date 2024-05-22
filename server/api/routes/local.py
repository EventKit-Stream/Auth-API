"""api.routes.LOGIN
File: login.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the handlers for the login routes.
"""

import os
import re
from asyncio import sleep
from datetime import datetime, timezone
from email_validator import validate_email, EmailNotValidError
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Form,
    HTTPException,
    status,
    Request,
)
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm

from models import FetchedUserInDB, User, UserInDB
from api.routes.users import get_current_active_user
from core.config import settings, log
from core.email import (
    send_reset_password_email,
    send_notification_change_password_email,
    send_verification_email,
)
from core.security import (
    Token,
    TokenData,
    decode_access_token,
    get_password_hash,
    verify_password,
    create_access_token,
)
from core.db import (
    create_user,
    fetch_user_by_id,
    remove_user_by_id,
    update_user_by_id,
    get_new_local_uuid,
    fetch_local_user_by_email,
    fetch_local_user_by_name,
    fetch_twitch_user_by_email,
    fetch_google_user_by_email,
)


# ~~~~ Helper Functions ~~~~ #


async def is_valid_username(username: str):
    """Validate the username format.
    It must be at least 5 characters long, and can only contain lowercase letters, numbers, and underscores.

    Args:
        username (str): The username to validate.

    Returns:
        bool: True if the username is valid, False otherwise.
    """
    username_pattern = r"^[a-z0-9_]{5,}$"
    return re.match(username_pattern, username) is not None


async def is_valid_full_name(full_name: str, username: str):
    """Validate the full_name format.
    It must match the username (capitalization and replacement of '_' with ' ', '-', '|', '.' are allowed).

    Args:
        full_name (str): The full name to validate.
        username (str): The username to match the full name with.
    """

    def username_to_fullname_pattern(
        username,
    ):  # Switches underscores in the username with the allowed characters for full_name and Lowercase and Uppercase letters
        # Escape any regex special characters in the username
        escaped_username = re.escape(username)
        # Replace underscores in the username with the allowed characters for full_name,
        # and also include the underscore itself
        pattern = escaped_username.replace("_", "[_ .|\\-]")
        # Create a regex that allows both upper and lower case letters, and also numbers
        pattern = re.sub(
            r"[a-z]", lambda x: f"[{x.group().lower()}{x.group().upper()}]", pattern
        )
        # Full regex that wraps the transformed username pattern
        return f"^{pattern}$"

    pattern = username_to_fullname_pattern(username)
    return re.match(pattern, full_name) is not None


async def email_validation(email: str):
    """Email validation function.

    Args:
        email (str): The email to validate.

    Returns:
        bool: True if the email is valid, False otherwise.
    """
    try:
        email_info = validate_email(email, check_deliverability=True)
        return email_info.normalized
    except EmailNotValidError:
        return None


async def is_password_strong(password: str):
    """Password validation function.

    Args:
        password (str): The password to validate.

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_405_METHOD_NOT_ALLOWED - Email not verified (for login with email)
        HTTPException: HTTP_401_UNAUTHORIZED - Incorrect password

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\d\s]).{8,}$"
    return re.match(password_pattern, password) is not None


async def authenticate_user(username: str, password: str):
    """Authenticate the user with the username or email and password.

    Args:
        username (str): The username or email of the user.
        password (str): The password of the user.

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_405_METHOD_NOT_ALLOWED - Email not verified (for login with email)
        HTTPException: HTTP_401_UNAUTHORIZED - Incorrect password

    Returns:
        FetchedUserInDB: The FULL user object if the authentication is successful.
    """
    user = await fetch_local_user_by_name(username)
    if not user:
        user = await fetch_local_user_by_email(username)
        if not user:
            log.debug(f"Failed login attempt for {username}, waiting for 2 seconds.")
            await sleep(2)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "Unauthorized",
                    "error_description": str(
                        {
                            "error": "User not found",
                            "error_description": "The user does not exist (not found with username or email).",
                        }
                    ),
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not user.local_email_verified:
            log.debug(f"Failed login attempt for {username}, waiting for 2 seconds.")
            await sleep(2)
            raise HTTPException(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                detail={
                    "error": "Unauthorized",
                    "error_description": str(
                        {
                            "error": "Email not verified",
                            "error_description": "You have to verify your email to be able to login with it.",
                        }
                    ),
                },
                headers={"WWW-Authenticate": "Bearer"},
            )
    if not await verify_password(password, user.hashed_password):
        log.debug(f"Failed login attempt for {username}, waiting for 2 seconds.")
        await sleep(2)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "error_description": str(
                    {
                        "error": "Incorrect password",
                        "error_description": "The password is incorrect.",
                    }
                ),
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


last_X_minutes_IPs = []


async def last_x_minutes_ip_check(host_ip: str):
    """Check if the IP has made too many requests in the last minutes.
    - If the IP has made more than 5 requests in the last 10 minutes,
        -> wait for 2 seconds before continuing.
    - If the IP has made more than 20 requests in the last 10 minutes,
        -> raise an HTTPException with status code 429.

    Args:
        host_ip (str): The IP address of the host.

    Raises:
        HTTPException: HTTP_429_TOO_MANY_REQUESTS - Too many requests
    """
    exception_ip = [
        "127.0.0.1",
        "localhost",
        "192.168.11.253",
        "192.168.11.254",
    ]  # NOTE remove or Update the exception IP
    if host_ip in exception_ip:
        log.debug(f"IP {host_ip} is in the exception list. No rate limiting.")
        return

    now = datetime.now(timezone.utc)
    time_limit = settings.LOGIN_ATTEMPTS_TIME
    wait_limit = settings.LOGIN_ATTEMPTS_WAIT
    error_limit = settings.LOGIN_ATTEMPTS_LIMIT
    for i, ip in enumerate(last_X_minutes_IPs):
        if (now - ip["time"]).seconds > time_limit * 60:
            last_X_minutes_IPs.pop(i)
    counter = 0
    for ip in last_X_minutes_IPs:
        if ip["ip"] == host_ip:
            counter += 1
    if counter > error_limit:
        log.error(
            f"Too many requests from {host_ip} in the last {time_limit} minutes. Blocking IP temporarily."
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "Too many requests",
                "error_description": f"Too many requests, please try again later (in {time_limit} minutes).",
            },
        )
    if counter > wait_limit:
        log.warning(
            f"Too many requests from {host_ip} in the last {time_limit} minutes. Waiting for 2 seconds."
        )
        await sleep(2)
    last_X_minutes_IPs.append({"ip": host_ip, "time": now})
    return


# ~~~~ ROUTE ~~~~ #

router = APIRouter()


@router.post("/register", response_model=Token)
async def register_user(
    request: Request,
    background_tasks: BackgroundTasks,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Register a new user.

    Args:
        username (str): Username of the user.
        password (str): Password of the user.
        confirm_password (str): Password confirmation.
        email (str): Email of the user.

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Passwords do not match or Invalid email
        HTTPException: HTTP_412_PRECONDITION_FAILED - Invalid username or password format
        HTTPException: HTTP_406_NOT_ACCEPTABLE - Username or email already taken
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Failed to create user

    Returns:
        Token: {"access_token": str, "token_type": str}
    """
    await last_x_minutes_ip_check(request.client.host)

    if password != confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Passwords do not match",
                "error_description": "The passwords do not match.",
            },
        )

    if not await is_valid_username(username):
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail={
                "error": "Invalid username",
                "error_description": "The username must be all lowercases and at least 5 characters long ('_' is accepted).",
            },
        )
    if not await is_password_strong(password):
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail={
                "error": "Invalid password",
                "error_description": "The password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
            },
        )

    email = await email_validation(email)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Invalid email",
                "error_description": "The email is not valid. Please provide a valid email address.",
            },
        )

    if await fetch_local_user_by_name(username):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail={
                "error": "Invalid username",
                "error_description": "The username is already taken. Please choose another one.",
            },
        )

    if await fetch_local_user_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail={
                "error": "Invalid email",
                "error_description": "The email is already taken. Please choose another one.",
            },
        )

    new_local_id = await get_new_local_uuid()
    new_user = UserInDB(
        disabled=False,
        updated_at=str(int(datetime.now(timezone.utc).timestamp())),
        login_method="local",
        full_name=username,
        local_id=new_local_id,
        local_username=username,
        local_email=email,
        local_email_verified=False,
        hashed_password=await get_password_hash(password),
    )
    new_user = await create_user(new_user)
    if not new_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to create user",
                "error_description": "Failed to create user.",
            },
        )
    background_tasks.add_task(send_verification_email, new_user)
    # background_tasks.add_task(send_new_account_email, newUser) # NOTE: Uncomment this line to send an email to the user
    return await create_access_token(
        subject=TokenData(
            uuid=new_user.uuid,
            login_method=new_user.login_method,
            platform_uuid=new_user.local_id,
            username=new_user.local_username,
            email=new_user.local_email,
        )
    )


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email_html():
    """Return the HTML content for the email verification callback.

    Returns:
        HTMLResponse: HTML content for the email verification callback.
    """
    html_file = os.path.join("assets/html/email-verification-callback.html")
    with open(html_file, "r", encoding="utf-8") as file:
        html_content = file.read()
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


@router.patch("/verify-email")
async def verify_email(token: str):
    """Verify the email of the user. It's called from the "black" email verification page.
    It checks if the user is a Twitch or Google user, and if so, checks to link them together.

    Args:
        token (str): The token to verify the email.

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_412_PRECONDITION_FAILED - Email verification failed (you need to have emails verified on both sides of the accounts you want to link)
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Failed to update user

    Returns:
        Response: {"message": "<message>"}
    """
    claims = await decode_access_token(token)
    sub: TokenData = claims["sub"]
    user = await fetch_user_by_id(sub.uuid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "User not found",
                "error_description": "The user does not exist.",
            },
        )
    is_twitch_user = await fetch_twitch_user_by_email(user.local_email)
    if is_twitch_user:
        if not is_twitch_user.twitch_email_verified:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail={
                    "error": "Email not verified",
                    "error_description": "You need to have your email verified on twitch also.",
                },
            )
        is_twitch_user.local_id = user.local_id
        is_twitch_user.local_username = user.local_username
        is_twitch_user.local_email = user.local_email
        is_twitch_user.local_email_verified = True
        is_twitch_user.hashed_password = user.hashed_password
        is_twitch_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
        updated_user = await update_user_by_id(is_twitch_user)
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "Failed to update user",
                    "error_description": "Failed to update user.",
                },
            )
        if not await remove_user_by_id(user.uuid):
            log.warning(f"Failed to remove user {user.uuid} after linking with Twitch.")
        return {"message": "Account successfully linked with Twitch."}

    is_google_user = await fetch_google_user_by_email(user.local_email)
    if is_google_user:
        if not is_google_user.google_email_verified:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail={
                    "error": "Email not verified",
                    "error_description": "You need to have your email verified on google also.",
                },
            )
        is_google_user.local_id = user.local_id
        is_google_user.local_username = user.local_username
        is_google_user.local_email = user.local_email
        is_google_user.local_email_verified = True
        is_google_user.hashed_password = user.hashed_password
        is_google_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
        updated_user = await update_user_by_id(is_google_user)
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "Failed to update user",
                    "error_description": "Failed to update user.",
                },
            )
        if not await remove_user_by_id(user.uuid):
            log.warning(f"Failed to remove user {user.uuid} after linking with Google.")
        return {"message": "Account successfully linked with Google."}

    user.local_email_verified = True
    updated_user = await update_user_by_id(user)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update user",
                "error_description": "Failed to update user.",
            },
        )
    return {"message": "Email verified successfully."}


@router.post("/login", response_model=Token)
async def login_for_access_token(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends()
):
    """Login the user and return an access token.

    Args:
        form_data (OAuth2PasswordRequestForm):
                Use ONLY the username and password (they are currently the only fields supported).

    Returns:
        Token: {"access_token": str, "token_type": str}
    """
    await last_x_minutes_ip_check(request.client.host)

    user = await authenticate_user(form_data.username, form_data.password)

    return await create_access_token(
        subject=TokenData(
            uuid=user.uuid,
            login_method=user.login_method,
            platform_uuid=user.local_id,
            username=user.local_username,
            email=user.local_email,
        )
    )


@router.patch("/me/password")
async def patch_password(
    background_tasks: BackgroundTasks,
    current_user: FetchedUserInDB = Depends(get_current_active_user),
    current_pwd: str = Form(...),
    new_pwd: str = Form(...),
    confirm_pwd: str = Form(...),
):
    """Update the password of the user.

    Args:
        current_pwd (str): The current password of the user.
        new_pwd (str): The new password of the user.
        confirm_pwd (str): The confirmation of the new password.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_400_BAD_REQUEST - Incorrect Password(s)
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Failed to update password

    Returns:
        Response: {"message": "Password updated successfully"}
    """
    try:
        assert await is_password_strong(new_pwd), "Password is not strong enough"
        assert await verify_password(
            current_pwd, current_user.hashed_password
        ), "Incorrect Password"
        assert (
            new_pwd != current_pwd
        ), "New password cannot be the same as the current password"
        assert new_pwd == confirm_pwd, "Passwords do not match"
    except AssertionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Failed to update password", "error_description": str(e)},
        ) from e

    current_user.hashed_password = await get_password_hash(new_pwd)
    current_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
    updated_user = await update_user_by_id(current_user)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update password",
                "error_description": "Unable to update the database",
            },
        )
    background_tasks.add_task(send_notification_change_password_email, current_user)
    return {"message": "Password updated successfully"}


@router.patch("/me", response_model=User)
async def patch_user(
    background_tasks: BackgroundTasks,
    current_user: FetchedUserInDB = Depends(get_current_active_user),
    full_name: str = Form(None),
    username: str = Form(None),
    email: str = Form(None),
):
    """_summary_

    Args:
        full_name (str, optional): The new full name of the user. (will be checked against the username format)
        username (str, optional): The new username of the user. (if no new full name is provided, it will reset it to the username)
        email (str, optional): The new email of the user. (a verification email will be sent if the email is different from the current one)

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_423_LOCKED - You cannot update the user information if you are connected through a third-party service.
        HTTPException: HTTP_412_PRECONDITION_FAILED - Invalid username or fullname format
        HTTPException: HTTP_406_NOT_ACCEPTABLE - Username already exists
        HTTPException: HTTP_400_BAD_REQUEST - Invalid email
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Failed to update user

    Returns:
        User: The full user object after the update.
    """
    if not current_user.login_method == "local":
        log.debug(f"User {current_user.username} is not a local user")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "error": "Failed to update user",
                "error_description": "You cannot update the user information if you are connected through a third-party service.",
            },
        )

    if username:
        if not await is_valid_username(username):
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail={
                    "error": "Failed to update user",
                    "error_description": "Invalid username, must be alphanumeric and contain at least 5 characters ('_' is accepted).",
                },
            )
        existing_user = await fetch_local_user_by_name(username)
        if existing_user and (existing_user.uuid != current_user.uuid):
            raise HTTPException(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                detail={
                    "error": "Failed to update user",
                    "error_description": "Username already exists",
                },
            )
        current_user.local_username = username
        current_user.full_name = username

    if full_name:
        if not await is_valid_full_name(full_name, current_user.local_username):
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail={
                    "error": "Failed to update user",
                    "error_description": "Invalid Full Name, it must match the username (capitalization and replacement of '_' with ' ', '-', '|', '.' are allowed)",
                },
            )
        current_user.full_name = full_name

    if email:
        try:
            email_info = validate_email(email, check_deliverability=True)
            email = email_info.normalized
        except EmailNotValidError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "Failed to update user",
                    "error_description": str(e),
                },
            ) from e
        if email != current_user.local_email:
            current_user.local_email_verified = False
            background_tasks.add_task(send_verification_email, current_user)
        current_user.local_email = email

    current_user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))

    updated_user = await update_user_by_id(current_user)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update user",
                "error_description": "Failed to update user in the database.",
            },
        )
    return updated_user


@router.post("/recover-password")
async def recover_password(
    background_tasks: BackgroundTasks, username: str = Form(...), email: str = Form(...)
):
    """Request for a password recovery email.

    Args:
        username (str): The username of the user.
        email (str): The email of the user.

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_401_UNAUTHORIZED - Invalid username or email (or unverified email)

    Returns:
        Response: {"message": "Password recovery email sent"}
    """
    user = await fetch_local_user_by_name(username)
    if not user:
        user = await fetch_local_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "User not found",
                    "error_description": "The user does not exist (not found with username or email).",
                },
            )
        if user.local_username != username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "Invalid username",
                    "error_description": "The usernames do not match.",
                },
            )
    if user.local_email != email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Invalid email",
                "error_description": "The emails do not match.",
            },
        )
    if not user.local_email_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Email not verified",
                "error_description": "You have to verify your email to be able to recover your password.",
            },
        )
    background_tasks.add_task(send_reset_password_email, user)
    return {"message": "Password recovery email sent"}


@router.post("/reset-password")
async def reset_password(
    background_tasks: BackgroundTasks,
    token: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Reset the password of the user.

    Args:
        token (str): the token to reset the password
        username (str): the username of the user
        email (str): the email of the user
        new_password (str): the new password
        confirm_password (str): the confirmation of the new password
        background_tasks ():

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - User not found
        HTTPException: HTTP_400_BAD_REQUEST - Failed to reset password
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - Failed to reset password

    Returns:
        Response: {"message": "Password reset successful"}
    """
    try:
        claims = await decode_access_token(token)
        sub: TokenData = claims["sub"]
        assert sub.username == username, "Invalid username"
        assert sub.email == email, "Invalid email"
        user = await fetch_user_by_id(sub.uuid)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "User not found",
                    "error_description": "The user does not exist.",
                },
            )
        assert user.local_username == username, "Invalid username"
        assert user.local_email == email, "Invalid email"
        assert await is_password_strong(new_password), "Password is not strong enough"
        assert new_password == confirm_password, "Passwords do not match"
        assert await verify_password(
            new_password, user.hashed_password
        ), "New password cannot be the same as the current password"
    except AssertionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Failed to reset password",
                "error_description": str(e),
            },
        ) from e

    user.hashed_password = await get_password_hash(new_password)
    user.updated_at = str(int(datetime.now(timezone.utc).timestamp()))
    updated_user = await update_user_by_id(user)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to reset password",
                "error_description": "Failed to update the database",
            },
        )
    background_tasks.add_task(send_notification_change_password_email, user)
    return {"message": "Password reset successful"}
