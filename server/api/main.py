"""api.MAIN
File: main.py
Author: LordLumineer
Date: 2024-04-24

Purpose: This file contains the main API Router that includes all the other routers.
"""
# NOTE: This is where we include all the routers that we have created.

from fastapi import APIRouter

from api.routes import login, users, utils, local, twitch, google, admin

api_router = APIRouter()
api_router.include_router(login.router, prefix="/id", tags=["login"])
api_router.include_router(local.router, prefix="/local", tags=["local"])
api_router.include_router(twitch.router, prefix="/twitch", tags=["twitch"])
api_router.include_router(google.router, prefix="/google", tags=["google"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(utils.router, prefix="/utils", tags=["utils"])
