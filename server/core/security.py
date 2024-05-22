"""core.SECURITY
File: security.py
Author: LordLumineer
Date: 2024-04-24

Purpose: This file handles the security of the API (creation, and validation of JWT, and hash and verification of passwords).
"""

from datetime import datetime, timedelta, timezone
import bcrypt
from authlib.jose import jwt
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer

from core.config import settings, log


ALGORITHM = settings.JWT_ALGORITHM
SECRET_KEY = settings.JWT_SECRET
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme_local = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_STR}/local/login",
    scheme_name="local",
    scopes={"local": "Local access"},
    description="Local access token",
    auto_error=True,
)


class TokenData(BaseModel):
    """Token Data Model"""

    uuid: str
    login_method: str
    platform_uuid: str
    username: str
    email: str


class Token(BaseModel):
    """Token Model"""

    access_token: str
    token_type: str


async def create_access_token(
    subject: TokenData,
    expires_delta: timedelta = ACCESS_TOKEN_EXPIRE_MINUTES,
    secret_key: str = SECRET_KEY,
):
    """Create a new access token for the user

    Args:
        subject (TokenData): Subject to be encoded in the token.
        expires_delta (timedelta, optional): expiration time of the token in minutes (default: 30 minutes)
        secret_key (str, optional): Secret key to use to encode the token. Defaults to SECRET_KEY.

    Returns:
        Token: {"access_token": str, "token_type": str}
    """
    header = {"alg": ALGORITHM, "token_type": "bearer"}
    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": str(subject),
        "exp": str(int(timedelta(minutes=expires_delta).total_seconds())),
        "iat": str(int(datetime.now(timezone.utc).timestamp())),
    }
    encoded_jwt = jwt.encode(header, payload, secret_key)
    return Token(access_token=encoded_jwt, token_type="bearer")


async def decode_access_token(token: str, secret_key: str = SECRET_KEY):
    """Decode the access token and validate it

    Args:
        token (str): Token to decode.
        secret_key (str, optional): Secret key to use to decode the token. Defaults to SECRET_KEY.

    Raises:
        Exception: Exception - Invalid token | {e} (to be cached by the caller)

    Returns:
        TokenData: {"uuid": str, "login_method": str, "platform_uuid": str, "username": str, "email": str}
    """
    try:
        claims = jwt.decode(s=token, key=secret_key)
    except (Exception, not claims) as e:
        log.warning(f"Invalid token | {e}")
        raise Exception(f"Invalid token | {e}") from e
    if claims["iss"] != settings.JWT_ISSUER:
        log.warning(f"Invalid issuer | {claims['iss']}")
        raise Exception(f"Invalid issuer | {claims['iss']}")
    iat = datetime.fromtimestamp(int(claims["iat"]), timezone.utc)
    if iat > datetime.now(timezone.utc):
        log.debug(
            f"Token issued in the future | {iat} | {datetime.now(timezone.utc).timestamp()}"
        )
        raise Exception("Token issued in the future")
    exp = timedelta(seconds=int(claims["exp"]))
    if iat + exp < datetime.now(timezone.utc):
        log.debug(
            f"Token has expired | {iat+exp} | {datetime.now(timezone.utc).timestamp()}"
        )
        raise Exception("Token has expired")
    claims["sub"] = TokenData(
        **dict(item.split("=") for item in claims["sub"].replace("'", "").split())
    )
    return claims


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check that an unencrypted password matches one that has previously been hashed"""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


async def get_password_hash(password: str) -> str:
    """Hash a password for the first time, with a randomly-generated salt"""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")
