"""MAIN
File: main.py
Author: LordLumineer
Date: 2024-04-24

Purpose: This file is the main entry point for the FastAPI application.
    It creates the FastAPI instance, sets up the CORS middleware, and includes the API router.
    It also defines the custom_generate_unique_id function to generate unique IDs for routes.
"""

import os
import signal
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.routing import APIRoute
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from starlette.middleware.cors import CORSMiddleware

from api.main import api_router
from api.routes.admin import get_current_admin_user
from core.config import settings, log
from core.db import disconnect, startup_auth_db
from core.engine import start_engine, engine, stop_engine

# [ ]: Implement Logging
# TODO: CI/CD Pipeline Testing
# TODO: Write the Unit Tests.


# from asyncio import sleep
# from tqdm import tqdm, trange
# delay_seconds = 15
# progress_step = 0.1
# pbar = tqdm(total=delay_seconds,
#            desc=f"Starting in {delay_seconds} seconds...",
#            position=0,
#            leave=True,
#            bar_format="{desc}: {remaining}s remaining |{percentage:3.0f}% {bar}"
#            )
# for i in range(delay_seconds*int(1/progress_step)):
#    await sleep(progress_step)
#    pbar.update(progress_step)
# pbar.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """This function is called when the application starts and stops. It is used to start and stop the engine."""
    log.info(f"{app.title} - is starting...")

    def tick():
        log.debug(f"Tick! The time is: {datetime.now()}")

    start_engine()
    engine.add_job(
        func=tick,
        trigger="interval",
        hours=1,
        name="Tick Job",
        id="tick_job",
        replace_existing=True,
    )
    if not await startup_auth_db():
        log.critical("Database is not running...")
        os.kill(os.getpid(), signal.SIGTERM)
        os._exit(1)
    yield  # This is when the application code will run
    log.info(f"{app.title} - Shutting down...")
    stop_engine()
    await disconnect()


def custom_generate_unique_id(route: APIRoute) -> str:
    """Custom function to generate unique IDs for routes."""
    return f"{route.tags[0]}-{route.name}"


tags_metadata = [
    {
        "name": "users",
        "description": "Operations with the user(s), regarding the Non-Critical Information.",
    },
    {
        "name": "login",
        "description": """Handles the backup login/register pages (local users ONLY). 
            <br>It can be used to validate the token.""",
        "externalDocs": {
            "description": "OAuth2",
            "url": "https://datatracker.ietf.org/doc/html/rfc6749",
        },
    },
    {
        "name": "local",
        "description": """Handles sensitive endpoints for Local Users. (authentication/registration/removal/password-updates)
            <br>It supports OAuth2 with password flow.""",
        "externalDocs": {
            "description": "OAuth2",
            "url": "https://datatracker.ietf.org/doc/html/rfc6749",
        },
    },
    {
        "name": "twitch",
        "description": "Operations regarding Twitch API.",
        "externalDocs": {
            "description": "OIDC authorization code grant flow",
            "url": "https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#oidc-authorization-code-grant-flow",
        },
    },
    {
        "name": "google",
        "description": "Operations regarding Google API.",
        "externalDocs": {
            "description": "Using OAuth 2.0 to Access Google APIs",
            "url": "https://developers.google.com/identity/protocols/oauth2",
        },
    },
    {"name": "admin", "description": "Connection for the Admins"},
    {
        "name": "utils",
        "description": "Utility functions for the API. Only accessible by the Admins.",
    },
]

# Create an instance of FastAPI
app = FastAPI(
    title=settings.PROJECT_NAME,
    summary="Event Kit Stream Auth API - FastAPI Implementation",
    description="""
        This api is used to authenticate users and manage user accounts for the Event Kit Stream application.
        The API provides endpoints for user registration, login, and account management.
        User data related to the Events is not managed by this API. refer to the Event Kit Stream API for that.
    """,
    version=settings.VERSION,
    openapi_tags=tags_metadata,
    docs_url=None,  # "/documentation",
    redoc_url=None,  # "/redocumentation",
    terms_of_service="https://legal.eventkit.stream/terms",  # TODO: Create the website
    contact={
        "name": "Support",
        "url": "https://github.com/EventKit-Stream/Auth-API/issues",
        "email": "support@evnentkit.stream",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
        "identifier": "Apache-2.0",
    },
    generate_unique_id_function=custom_generate_unique_id,
    lifespan=lifespan,
)
# Set all CORS enabled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_STR)


@app.get("/", include_in_schema=False, tags=["misc"])
async def root(request: Request):
    """Root endpoint for the API."""
    url_components = request.url.components
    return RedirectResponse(
        url=f"{url_components.scheme}://{url_components.hostname}/authorize",
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@app.get("/favicon.ico", include_in_schema=False, tags=["misc"])
async def favicon():
    """Return the favicon for the API."""
    return FileResponse(
        path="./assets/favicon.ico",
        media_type="image/x-icon",
        status_code=status.HTTP_200_OK,
    )


@app.get(f"{settings.API_STR}/admin/docs", include_in_schema=False, tags=["admin"])
async def custom_swagger_ui_html(token: str | None = None):
    """Custom Swagger UI HTML page for the Admins."""
    if not token:
        return RedirectResponse(
            url=f"{settings.API_STR}/admin/login",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )
    token_type = token.split(" ")[0]
    if token_type.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Invalid token type.",
                "error_description": "Expected: 'bearer <token>'.",
            },
        )
    access_token = token.split(" ")[1]
    try:
        if await get_current_admin_user(access_token):
            return get_swagger_ui_html(
                openapi_url=app.openapi_url,
                title=app.title + " - Swagger UI",
                oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
                swagger_js_url="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
                swagger_css_url="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css",
            )
    except HTTPException:
        return RedirectResponse(
            url=f"{settings.API_STR}/admin/login",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )

@app.get("/api_str", include_in_schema=False, tags=["misc"])
async def api_str():
    """Return the API_STR."""
    return {'api_str': settings.API_STR}

@app.get(app.swagger_ui_oauth2_redirect_url, include_in_schema=False, tags=["admin"])
async def swagger_ui_redirect():
    """Redirect to the Swagger UI OAuth2 redirect page."""
    return get_swagger_ui_oauth2_redirect_html()


@app.get(f"{settings.API_STR}/admin/redoc", include_in_schema=False, tags=["admin"])
async def redoc_html(token: str | None = None):
    """Custom ReDoc HTML page for the Admins."""
    if not token:
        return RedirectResponse(
            url=f"{settings.API_STR}/admin/login?redoc=true",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )
    token_type = token.split(" ")[0]
    if token_type.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Invalid token type.",
                "error_description": "Expected: 'bearer <token>'.",
            },
        )
    access_token = token.split(" ")[1]
    try:
        if await get_current_admin_user(access_token):
            return get_redoc_html(
                openapi_url=app.openapi_url,
                title=app.title + " - ReDoc",
                redoc_js_url="https://unpkg.com/redoc@next/bundles/redoc.standalone.js",
            )
    except HTTPException:
        return RedirectResponse(
            url=f"{settings.API_STR}/admin/login",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )


# Run the app using uvicorn
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=20)
