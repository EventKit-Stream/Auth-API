"""api.routes.UTILS
File: utils.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the handlers for the utility routes (these are endpoints that require to be an administrator to use).
"""

import io
from PIL import Image
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Response,
    UploadFile,
    status,
)

from api.routes.admin import get_current_admin_user
from models import AdminUser, FetchedUserInDB, UserInDB
from core.config import settings, log
from core.email import send_email_all, send_test_email
from core.security import (
    TokenData,
    create_access_token,
    decode_access_token,
    get_password_hash,
)
from core.db import (
    create_user,
    fetch_all_emails,
    fetch_user_by_id,
    remove_user_by_id,
    save_pfp,
    fetch_pfp,
    remove_pfp,
    update_user_by_id,
)

router = APIRouter()


@router.get("/sent-test-email")
async def sent_email(admin: AdminUser = Depends(get_current_admin_user)):
    """Endpoint to call to send a test email to the admin email.

    Headers:
        Authorization: Bearer {token}

    Returns:
        {"message": "Test email sent."}
    """
    await send_test_email(settings.ADMIN_EMAIL)
    return {"message": f"Test email sent - {admin.username} -> {settings.ADMIN_EMAIL}"}


@router.post("/send-global-email")
async def send_global_email(
    subject: str,
    content_html_file: UploadFile = File(...),
    admin: AdminUser = Depends(get_current_admin_user),
):
    """Endpoint to use to send a global email to all users.

    Args:
        subject (str): Subject of the email.
        content_html_file (UploadFile): It's the body of the email.

    Headers:
        Authorization: Bearer {token}

    Returns:
        list: Returns a list of all the emails that the email was sent to.
    """
    content = await content_html_file.read()
    content = content.decode("utf-8")
    log.critical(f"ADMIN: {admin} - Sending global email.")
    emails = await fetch_all_emails()
    email_str = "+".join(emails)
    await send_email_all(emails, subject, content)
    return email_str


@router.get("/pwd-hash")
async def pwd_user(pwd: str, admin: AdminUser = Depends(get_current_admin_user)):
    """Endpoint to create a password hash, especially useful when forcefully changing a password in the database is needed.

    Args:
        pwd (str): The password to hash.

    Headers:
        Authorization: Bearer {token}

    Returns:
        str: The hashed password.
    """
    log.warning(f"ADMIN: {admin} - Creating Password Hash.")
    return await get_password_hash(pwd)


@router.post("/jwt-token")
async def jwt_token(
    subject: TokenData,
    expires_delta: int,
    secret: str,
    admin: AdminUser = Depends(get_current_admin_user),
):
    """Similarity to the password hash, this endpoint is used to create a JWT token.

    Args:
        subject (TokenData): a Pydantic model that contains the data to be stored in the token.
        expires_delta (int): the expiration time of the token (in minutes).
        secret (str): The secret to use to sign the token.

    Headers:
        Authorization: Bearer {token}

    Returns:
        Token: {"token_type": str, "access_token": str}
    """
    log.warning(f"ADMIN: {admin} - Creating Password Hash.")
    return await create_access_token(subject, expires_delta, secret)


# ~~ User Handling ~~


async def validation_of_user(uuid: str, token: str):
    """Function to validate the user data from a uuid and a token.

    Args:
        uuid (str): Id of the user.
        token (str): access token related to the user.

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - if the user is not found.

    Returns:
        FetchedUserInDB: The most COMPLETE user data (ID, default user data, local, twitch and google user data).
    """
    claims = await decode_access_token(token, settings.JWT_MAIN_SERVICE_SECRET)
    sub: TokenData = claims["sub"]
    if sub.uuid != uuid:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "User not found",
                "error_description": "Invalid token data. Incorrect ID.",
            },
        )
    user = await fetch_user_by_id(sub.uuid)
    try:
        assert user is not None, "User not found."
        assert user.uuid == sub.uuid, "User ID mismatch."
        assert user.login_method == sub.login_method, "Login method mismatch."
        match sub.login_method:
            case "local":
                assert user.local_id == sub.platform_uuid, "Platform UUID mismatch."
                assert user.local_email == sub.email, "Email mismatch."
                assert user.local_username == sub.username, "Username mismatch."
            case "twitch":
                assert user.twitch_id == sub.platform_uuid, "Platform UUID mismatch."
                assert user.twitch_email == sub.email, "Email mismatch."
                assert user.twitch_username == sub.username, "Username mismatch."
            case "google":
                assert user.google_id == sub.platform_uuid, "Platform UUID mismatch."
                assert user.google_email == sub.email, "Email mismatch."
                assert user.google_username == sub.username, "Username mismatch."
            case _:
                raise AssertionError("Invalid login method.")
    except AssertionError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "User not found",
                "error_description": str(e),
            },
        ) from e
    return user


@router.post("/new-user")
async def new_user(
    shared_token: str,
    user: UserInDB,
    admin: AdminUser = Depends(get_current_admin_user),
):
    """Endpoint to create a new user. This endpoint will be used by the external approved/registered services to create new users.

    Args:
        shared_token (str): The token to validate the integrity of the parameters.
        user (UserInDB): The user structure to be created.

    Headers:
        Authorization: Bearer {token}

    Returns:
        FetchedUserInDB: The most COMPLETE user data (ID, default user data, local, twitch and google user data).
    """
    log.warning(f"ADMIN: {admin} - Creating new user: {user}")
    await decode_access_token(shared_token, settings.JWT_MAIN_SERVICE_SECRET)
    created_user = await create_user(user)
    return created_user


@router.get("/fetch-user/{user_id}")
async def fetch_user(
    shared_token: str, user_id: str, admin: AdminUser = Depends(get_current_admin_user)
):
    """Get the user data from the user_id. This endpoint is used to fetch the user data for the admin panel.

    Args:
        shared_token (str): The token to validate the integrity of the parameters.
        user_id (str): The ID of the user to fetch.

    Headers:
        Authorization: Bearer {token}

    Returns:
        FetchedUserInDB: Ref. api.routes.utils.new_user()
    """
    log.warning(f"ADMIN: {admin} - Fetching user: {user_id}")
    user = await validation_of_user(user_id, shared_token)
    return user


@router.patch("/update-user/{user_id}")
async def update_user(
    shared_token: str,
    user_id: str,
    user: UserInDB,
    admin: AdminUser = Depends(get_current_admin_user),
):
    """Update the user data from the user_id. This endpoint is used to update the user data for the admin panel.

    Args:
        shared_token (str): The token to validate the integrity of the parameters.
        user_id (str): ID of the user to update.
        user (UserInDB): The user structure to use to update the user.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the user was not updated.

    Returns:
        FetchedUserInDB: Ref. api.routes.utils.new_user()
    """
    log.warning(f"ADMIN: {admin} - Updating user: {user}")
    await validation_of_user(user_id, shared_token)
    user = FetchedUserInDB(**user.model_dump(), uuid=user_id)
    updated_user = await update_user_by_id(user)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update user.",
                "error_description": "User data was not updated.",
            },
        )
    return updated_user


@router.delete("/delete-user/{user_id}")
async def delete_user(
    shared_token: str, user_id: str, admin: AdminUser = Depends(get_current_admin_user)
):
    """Delete the user data from the user_id. This endpoint is used to delete the user data for the admin panel.

    Args:
        shared_token (str): The token to validate the integrity of the parameters.
        user_id (str): ID of the user to delete.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the user was not deleted.

    Returns:
        {"message": "User deleted successfully"}
    """
    log.warning(f"ADMIN: {admin} - Deleting user: {user_id}")
    await validation_of_user(user_id, shared_token)
    result = await remove_user_by_id(user_id)
    if result:
        return {"message": "User deleted successfully"}

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error": "Failed to delete user.",
            "error_description": "User data was not deleted.",
        },
    )


# ~~ Image Handling ~~


@router.post("/upload-image")
async def upload_image(
    file: UploadFile = File(...), admin: AdminUser = Depends(get_current_admin_user)
):
    """Manually upload an image to the database.

    Args:
        file (UploadFile): The image file to upload to the database.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the image was not saved.

    Returns:
        {"filename": file.filename, "id": str(image_id)}
    """
    image_data = await file.read()
    image = Image.open(io.BytesIO(image_data))

    # Convert image to the format that can be stored in MongoDB
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format=image.format)
    img_byte_arr = img_byte_arr.getvalue()

    # Store in MongoDB
    image_id = await save_pfp(file.filename, img_byte_arr)
    if not image_id:
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to save image.",
                "error_description": f"Failed to save image. - {admin.username}",
            },
        )

    return {"filename": file.filename, "id": str(image_id)}


@router.patch("/update-image/{image_id}")
async def update_image(
    image_id: str,
    file: UploadFile = File(...),
    admin: AdminUser = Depends(get_current_admin_user),
):
    """Manually update an image in the database.

    Args:
        image_id (str): ID of the image to update.
        file (UploadFile): The image file to update in the database.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the image was not updated.

    Returns:
        {"filename": file.filename, "id": str(image_id)}
    """
    image_data = await file.read()
    image = Image.open(io.BytesIO(image_data))

    # Convert image to the format that can be stored in MongoDB
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format=image.format)
    img_byte_arr = img_byte_arr.getvalue()

    # Update in MongoDB
    image_id = await save_pfp(file.filename, img_byte_arr, image_id)
    if not image_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update image.",
                "error_description": f"Failed to update image. - {admin.username}",
            },
        )
    return {"filename": file.filename, "id": str(image_id)}


@router.get("/retrieve-image/{image_id}")
async def retrieve_image(
    image_id: str, admin: AdminUser = Depends(get_current_admin_user)
):
    """Manually retrieve an image from the database.

    Args:
        image_id (str): ID of the image to retrieve.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - if the image was not found.

    Returns:
        PNG: Response(content=img_byte_arr, media_type="image/png")
    """
    image_data = await fetch_pfp(image_id)
    if image_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "Image not found.",
                "error_description": f"Image not found. - {admin.username}",
            },
        )

    img = Image.open(io.BytesIO(image_data["image"]))
    img_byte_arr = io.BytesIO()
    # Convert to PNG or appropriate format
    img.save(img_byte_arr, format="PNG")
    img_byte_arr = img_byte_arr.getvalue()

    return Response(content=img_byte_arr, media_type="image/png")


@router.delete("/delete-image/{image_id}")
async def delete_image(
    image_id: str, admin: AdminUser = Depends(get_current_admin_user)
):
    """Manually delete an image from the database.

    Args:
        image_id (str): ID of the image to delete.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the image was not deleted.

    Returns:
        {"message": "Image deleted."}
    """
    result = await remove_pfp(image_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to delete image.",
                "error_description": f"Failed to delete image. - {admin.username}",
            },
        )
    return {"message": "Image deleted."}
