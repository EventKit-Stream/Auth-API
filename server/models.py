"""MODELS
File: models.py
Author: LordLumineer
Date: 2024-04-24

Purpose: This file contains the Pydantic models for the API and the DataBase.
"""

from pydantic import BaseModel, EmailStr


# ~~ Users ~~ #
class User(BaseModel):
    """Common parts of the User Pydantic model for the API."""
    disabled: bool | None = None
    updated_at: str | None = None
    login_method: str | None = None
    full_name: str | None = None
    picture_id: str | None = None


class LocalUser(BaseModel):
    """Local parts of the User Pydantic model for the API."""
    local_id: str | None = None
    local_username: str | None = None
    local_email: EmailStr | None = None
    local_email_verified: bool | None = None
    hashed_password: str | None = None


class TwitchUser(BaseModel):
    """Twitch parts of the User Pydantic model for the API."""
    twitch_id: str | None = None
    twitch_username: str | None = None
    twitch_email: EmailStr | None = None
    twitch_email_verified: bool | None = None
    twitch_scope: list[str] | None = ["user:read:email", "openid"]


class GoogleUser(BaseModel):
    """Google parts of the User Pydantic model for the API."""
    google_id: str | None = None
    google_username: str | None = None
    google_email: EmailStr | None = None
    google_email_verified: bool | None = None
    google_scope: list[str] | None = None


class UserInDB(User, LocalUser, TwitchUser, GoogleUser):
    """User Pydantic model for the DataBase."""

class FetchedUserInDB(UserInDB):
    """User Pydantic model for the DataBase with the UUID."""
    uuid: str | None = None


class AdminUser(BaseModel):
    """Admin User Pydantic model for the API."""
    username: str | None = None
    hashed_password: str | None = None
