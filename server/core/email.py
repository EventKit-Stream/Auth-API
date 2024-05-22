"""core.EMAIL
File: email.py
Author: LordLumineer
Date: 2024-04-24

Purpose: This contains the email sending functions for the API.
"""

import smtplib
from email.mime.text import MIMEText
from jinja2 import Template

from models import FetchedUserInDB
from core.config import settings, log
from core.security import Token, TokenData, create_access_token

sender = settings.EMAIL_ADDRESS
sender_pwd = settings.EMAIL_PASSWORD
smtp_server = settings.EMAIL_SMTP_SERVER
smtp_port = settings.EMAIL_SMTP_PORT


async def send_email(receiver: str, subject: str, html_content: str):
    """Send a Single Email to a Receiver.

    Args:
        receiver (str): Email Address of the Receiver.
        subject (str): Subject of the Email.
        html_content (str): HTML Content of the Email.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    html_message = MIMEText(html_content, "html")
    html_message["Subject"] = subject
    html_message["From"] = sender
    html_message["To"] = receiver

    with smtplib.SMTP(host=smtp_server, port=smtp_port) as server:
        server.starttls()
        server.login(sender, sender_pwd)
        server.sendmail(sender, receiver, html_message.as_string())
        server.quit()
    log.success(f"Email Sent to {receiver}")
    return True


async def send_email_all(emails: list[str], subject: str, html_content: str):
    """Send a Single Email to Multiple Receivers. (Bulk Emailing)

    Args:
        emails (list[str]): List of Email Addresses of the Receivers.
        subject (str): Subject of the Email.
        html_content (str): HTML Content of the Email.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    with smtplib.SMTP(host=smtp_server, port=smtp_port) as server:
        server.starttls()
        server.login(sender, sender_pwd)
        for email in emails:
            html_message = MIMEText(html_content, "html")
            html_message["Subject"] = subject
            html_message["From"] = f"EventKit <{sender}>"
            html_message["To"] = f"me <{email}>"
            html_message["Reply-To"] = sender
            server.send_message(html_message)
        server.quit()
    log.success(f"Email Sent to {emails}")
    return True


async def send_db_alert_email(receiver: str = settings.ADMIN_EMAIL):
    """Send an Email to the Admin when the Database is not Running.

    Args:
        receiver (str, optional): Email Address of the Receiver. Defaults to settings.ADMIN_EMAIL.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    with open("./assets/html/email/DB_not_running.html", "r", encoding="utf-8") as f:
        template = Template(f.read())
    context = {"project_name": settings.PROJECT_NAME}
    html = template.render(context)
    log.info(f"DB not running Email {sender} to {receiver}")
    await send_email(receiver, "URGENT - DB not running", html)
    return True


async def send_test_email(receiver: str):
    """Send a Test Email to the Receiver.

    Args:
        receiver (str): Email Address of the Receiver.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    with open("./assets/html/email/test_email.html", "r", encoding="utf-8") as f:
        template = Template(f.read())
    context = {"project_name": settings.PROJECT_NAME, "email": sender}
    html = template.render(context)
    log.info(f"Testing Email {sender} to {receiver}")
    await send_email(receiver, "Test Email", html)
    return True


async def send_reset_password_email(user: FetchedUserInDB):
    """Send a Reset Password Email to the User.

    Args:
        user (FetchedUserInDB): User that needs to Reset the Password.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    token: Token = await create_access_token(
        subject=TokenData(
            uuid=user.uuid,
            login_method=user.login_method,
            platform_uuid=user.local_id,
            username=user.local_username,
        ),
        expires_delta=15,
    )

    with open("./assets/html/email/reset_password.html", "r", encoding="utf-8") as f:
        template = Template(f.read())
    context = {
        "project_name": settings.PROJECT_NAME,
        "username": user.full_name,
        "link": f"{settings.API_URI}/authorize/reset-password?token={token.access_token}",
        "valid_minutes": "15",
    }
    html = template.render(context)
    log.info(f"Sending Reset Password Email to {user.local_email}")
    await send_email(user.local_email, "Reset Password", html)
    return True


async def send_verification_email(user: FetchedUserInDB):
    """Send a Verification Email to the User.

    Args:
        user (FetchedUserInDB): User that needs to Verify the Email.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    token: Token = await create_access_token(
        subject=TokenData(
            uuid=user.uuid,
            email=user.local_email,
            login_method=user.login_method,
            platform_uuid=user.local_id,
            username=user.local_username,
        ),
        expires_delta=settings.EMAIL_VERIFICATION_EXPIRE_MINUTES,
    )
    expire_hours = int(settings.EMAIL_VERIFICATION_EXPIRE_MINUTES / 60)
    with open(
        "./assets/html/email/verification_email.html", "r", encoding="utf-8"
    ) as f:
        template = Template(f.read())
    context = {
        "project_name": settings.PROJECT_NAME,
        "username": user.full_name,
        "email": user.local_email,
        "link": f"{settings.API_URI}{settings.API_STR}/local/verify-email?token={token.access_token}",
        "valid_hours": str(expire_hours),
    }
    html = template.render(context)
    log.info(f"Sending Verification Email to {user.local_email}")
    await send_email(user.local_email, "Verification Email", html)
    return True


async def send_new_account_email(user: FetchedUserInDB):
    """Send a New Account Email to the User.

    Args:
        user (FetchedUserInDB): User that has Created a New Account.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    with open("./assets/html/email/new_account.html", "r", encoding="utf-8") as f:
        template = Template(f.read())
    context = {
        "project_name": settings.PROJECT_NAME,
        "username": user.full_name,
        "link": "https://eventkit.stream/dashboard",
    }
    html = template.render(context)
    email = ""
    match user.login_method:
        case "local":
            email = user.local_email
        case "google":
            email = user.google_email
        case "twitch":
            email = user.twitch_email
        case _:
            log.error(f"Unknown login method {user.login_method}")
            return False

    log.info(f"Sending New Account Email to {email}")
    await send_email(email, "New Account", html)
    return True


async def send_notification_change_password_email(user: FetchedUserInDB):
    """Send a Notification Email to the User when Password is Changed.

    Args:
        user (FetchedUserInDB): User that has Changed the Password.

    Returns:
        bool: True if Email is Sent Successfully.
    """
    with open(
        "./assets/html/email/notification_pwd_change.html", "r", encoding="utf-8"
    ) as f:
        template = Template(f.read())
    context = {
        "project_name": settings.PROJECT_NAME,
        "username": user.full_name,
    }
    html = template.render(context)
    log.info(f"Sending Change Password Email to {user.local_email}")
    await send_email(user.local_email, "Change Password", html)
    return True
