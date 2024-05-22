"""api.routes.LOGIN
File: login.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the handlers for the login routes.

NOTE: OPTIONAL: /authorize (fused login and signup page)
"""

from jinja2 import Template
from fastapi import APIRouter, Depends, status
from fastapi.responses import HTMLResponse

from core.config import settings
from models import FetchedUserInDB
from api.routes.users import get_current_active_user


router = APIRouter()


@router.get("/validate-token", status_code=status.HTTP_202_ACCEPTED)
async def validate_token(
    current_user: FetchedUserInDB = Depends(get_current_active_user),
):
    """Simple endpoint to validate the token.

    Headers:
        Authorization: Bearer {token}

    Returns:
        Response: {"message": "Token is valid"} if the token is valid.
    """
    return {"message": f"Token is valid - {current_user.uuid}"}


@router.get("/authorize/login")
async def login_page(redirect_uri: str = None, state: str = None):
    """Renders the login page.

    Args:
        redirect_uri (str, optional): Page to redirect once logged Up.
        state (str, optional): State to pass to the redirect_uri.

    Returns:
        HTMLResponse: The login page.
    """
    with open("./assets/html/template/login.html", encoding="utf-8") as f:
        template = Template(f.read())
    context = {
        "API_STR": settings.API_STR,
    }
    html_content = template.render(context)
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


@router.get("/authorize/register")
async def register_page(redirect_uri: str = None, state: str = None):
    """Renders the register page.

    Args:
        redirect_uri (str, optional): Page to redirect once Signed Up.
        state (str, optional): State to pass to the redirect_uri.

    Returns:
        HTMLResponse: The register page.
    """
    with open("./assets/html/template/register.html", encoding="utf-8") as f:
        template = Template(f.read())
    context = {
        "API_STR": settings.API_STR,
    }
    html_content = template.render(context)
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)
