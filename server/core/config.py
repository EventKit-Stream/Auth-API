"""core.CONFIG
File: config.py
Author: LordLumineer
Date: 2024-05-04

Purpose: This file contains the Settings Configuration for the API.
    It loads the sensitive information from the .ENV file (if declared in both the ones in the .ENV file are used).
    Be Careful: any variable declared in the .ENV file must be declared in the Settings class. (e.g. SECRET: str)
"""

import os
from typing import List
from datetime import timedelta, time
from loguru import logger
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings Configuration for the API."""

    model_config = SettingsConfigDict(env_file="./.env", env_file_encoding="utf-8")
    PROJECT_NAME: str = "Event Kit Stream Authentication API"
    VERSION: str = "1.0.0"
    API_URI: str = "https://id.eventkit.stream"
    API_STR: str = "/v1"
    ADMIN_EMAIL: str

    LOGS_LEVEL: str | int = "DEBUG"
    LOGS_PATH: str = "./db/logs"

    DATABASE_BACKUP_PATH: str = "./db/backup"
    DATABASE_BACKUP_TIME: List[int] = [0, 0]
    DATABASE_HOST: str
    DATABASE_PORT: str
    DATABASE_USERNAME: str
    DATABASE_PASSWORD: str
    DATABASE_BACKUP_RETENTION: int = 7
    MAX_IMAGE_SIZE: int = 524288 

    EMAIL_SMTP_SERVER: str
    EMAIL_SMTP_PORT: int
    EMAIL_ADDRESS: str
    EMAIL_PASSWORD: str
    EMAIL_VERIFICATION_EXPIRE_MINUTES: int = 1440

    JWT_ALGORITHM: str = "HS256"
    JWT_SECRET: str
    JWT_MAIN_SERVICE_SECRET: str
    JWT_ISSUER: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    LOGIN_ATTEMPTS_TIME: int = 10
    LOGIN_ATTEMPTS_WAIT: int = 5
    LOGIN_ATTEMPTS_LIMIT: int = 20

    TWITCH_CLIENT_ID: str
    TWITCH_CLIENT_SECRET: str
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str


settings = Settings()

logger.add(
    os.path.join(settings.LOGS_PATH, "{time}.log"),
    rotation=time(0, 0),
    compression="zip",
    serialize=True,
    retention=timedelta(days=7),
    level=settings.LOGS_LEVEL,
    enqueue=True,
)
log = logger
