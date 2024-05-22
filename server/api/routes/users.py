"""api.routes.USERS
File: users.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the handlers for the user routes.
"""

import io
from datetime import datetime, timezone
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

from models import FetchedUserInDB, User
from core.config import settings
from core.security import oauth2_scheme_local, decode_access_token, TokenData
from core.db import (
    fetch_user_by_id,
    remove_user_by_id,
    update_user_by_id,
    save_pfp,
    fetch_pfp,
    remove_pfp,
)


# ~~~~ Helper Functions ~~~~ #


async def get_current_user(token: str = Depends(oauth2_scheme_local)):
    """Get the current user from the token.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_401_UNAUTHORIZED - if the token is invalid.

    Returns:
        FetchedUserInDB: The full user object.
    """
    try:
        claims = await decode_access_token(token)
        sub: TokenData = claims["sub"]
        user = await fetch_user_by_id(sub.uuid)
        if user is None:
            raise Exception("User not found")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Could not validate credentials",
                "error_description": f"Invalid token: {e}",
            },
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    """Filter the current user to check if it is active (if not disabled).

    Args:
        current_user (User): The current user object.

    Raises:
        HTTPException: HTTP_423_LOCKED - if the user is disabled.

    Returns:
        User: The small user object.
    """
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={"error": "Inactive user", "error_description": "User is Disabled"},
        )
    return current_user


# ~~~~ ROUTE ~~~~ #

router = APIRouter()


@router.get("/me", response_model=User)
async def get_user(
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Simple GET request to get the current user.

    Headers:
        Authorization: Bearer {token}

    Returns:
        User: The current user object. (small object)
    """
    return current_user


@router.delete("/me")
async def delete_user(
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Delete the current user.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the user could not be deleted.

    Returns:
        Response: {"message": "User deleted successfully"}
    """
    if not await remove_user_by_id(current_user.uuid):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to delete user",
                "error_description": "Failed to delete user from database",
            },
        )
    return {"message": "User deleted successfully"}


@router.post("/pfp")
async def upload_profile_picture(
    file: UploadFile = File(...),
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Upload a profile picture for the user.

    Args:
        file (UploadFile): The image file to upload.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_413_REQUEST_ENTITY_TOO_LARGE - if the image is too large.
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the image could not be saved.

    Returns:
        User: Small user object.
    """
    if file.size > settings.MAX_IMAGE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "Image too large",
                "error_description": "Image size must be less than 512KB",
            },
        )
    name_to_use = "pfp"
    match current_user.login_method:
        case "google":
            name_to_use = current_user.google_username
        case "twitch":
            name_to_use = current_user.twitch_username
        case "local":
            name_to_use = current_user.full_name
        case _:
            name_to_use = current_user.full_name.lower().replace(" ", "_").replace(".", "_").replace("-", "_").replace("|", "_")
    file.filename = f"pfp_{name_to_use}_{int(datetime.now(timezone.utc).timestamp())}_{file.filename}"
    image_data = await file.read()
    image = Image.open(io.BytesIO(image_data))

    # Convert image to the format that can be stored in MongoDB
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format=image.format)
    img_byte_arr = img_byte_arr.getvalue()
    # Store in MongoDB
    if current_user.picture_id:
        image_id = await save_pfp(file.filename, img_byte_arr, current_user.picture_id)
        if image_id:
            return current_user
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update image",
                "error_description": "Failed to update image in database",
            },
        )
    image_id = await save_pfp(file.filename, img_byte_arr)
    if not image_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to save image",
                "error_description": "Failed to save image in database",
            },
        )

    current_user.picture_id = image_id
    updated_user = await update_user_by_id(current_user)
    updated_user = User(**updated_user.model_dump())
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update user",
                "error_description": "Failed to update user in database",
            },
        )
    return updated_user


@router.patch("/pfp")
async def update_profile_picture(
    file: UploadFile = File(...), current_user: User = Depends(get_current_active_user)
):
    """Update the profile picture of the user.

    Args:
        file (UploadFile): The image file to upload.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the image could not be updated.

    Returns:
        User: Small user object.
    """
    name_to_use = "pfp"
    match current_user.login_method:
        case "google":
            name_to_use = current_user.google_username
        case "twitch":
            name_to_use = current_user.twitch_username
        case "local":
            name_to_use = current_user.full_name
        case _:
            name_to_use = current_user.full_name.lower().replace(" ", "_").replace(".", "_").replace("-", "_").replace("|", "_")
    file.filename = f"pfp_{name_to_use}_{int(datetime.now(timezone.utc).timestamp())}_{file.filename}"
    image_data = await file.read()
    image = Image.open(io.BytesIO(image_data))

    # Convert image to the format that can be stored in MongoDB
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format=image.format)
    img_byte_arr = img_byte_arr.getvalue()

    # Update in MongoDB
    image_id = await save_pfp(file.filename, img_byte_arr, current_user.picture_id)
    if image_id:
        return current_user
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={
            "error": "Failed to update image",
            "error_description": "Failed to update image in database",
        },
    )


@router.get("/pfp")
async def get_profile_picture(
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Get the profile picture of the user.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_404_NOT_FOUND - if the image is not found.

    Returns:
        image/png: The image file.
    """
    image_data = await fetch_pfp(current_user.picture_id)
    if image_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "Image not found",
                "error_description": "Image not found.",
            },
        )

    img = Image.open(io.BytesIO(image_data["image"]))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")  # Convert to PNG or appropriate format
    img_byte_arr = img_byte_arr.getvalue()

    return Response(
        content=img_byte_arr, media_type="image/png", status_code=status.HTTP_200_OK
    )


@router.delete("/pfp")
async def delete_profile_picture(current_user: User = Depends(get_current_active_user)):
    """Delete the profile picture of the user.

    Headers:
        Authorization: Bearer {token}

    Raises:
        HTTPException: HTTP_500_INTERNAL_SERVER_ERROR - if the image could not be deleted. or Update the user.

    Returns:
        User: Small user object.
    """
    result = await remove_pfp(current_user.picture_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to delete image",
                "error_description": "Failed to delete image from database",
            },
        )
    current_user.picture_id = None
    updated_user = await update_user_by_id(current_user)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Failed to update user",
                "error_description": "Failed to update user in database",
            },
        )
    return updated_user
