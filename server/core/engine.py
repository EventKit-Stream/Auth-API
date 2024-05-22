"""core.ENGINE
File: engine.py
Author: LordLumineer
Date: 2024-04-24

Purpose: This file contains the Engine Configuration for the API. runs the scheduler for the API.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from core.config import log

engine = AsyncIOScheduler()


def start_engine():
    """Start the Engine."""
    log.info("Starting Engine...")
    engine.start()


def stop_engine():
    """Stop the Engine."""
    current_jobs = engine.get_jobs()
    for job in current_jobs:
        log.warning(f"Removing Job: {job.id} | {job.name}")
        job.remove()
    log.warning("Stopping Engine...")
    engine.shutdown()
