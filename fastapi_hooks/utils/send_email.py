import secrets
import aiosmtplib
from email.message import EmailMessage

BASE_MAGIC_LINK_URL = "https://yourapp.com/magic-login?token="  # your magic link base URL

async def send_email(config:dict,to_email: str, method: str = None) -> dict | None:
    if method == "magic-link":
        token = secrets.token_urlsafe(32)
        magic_link = f"{BASE_MAGIC_LINK_URL}{token}"

        subject = "Your Magic Login Link"
        body = f"""
        <html>
          <body>
            <p>Hello,</p>
            <p>Click the link below to login:</p>
            <p><a href="{magic_link}">{magic_link}</a></p>
            <p>If you did not request this, please ignore this email.</p>
          </body>
        </html>
        """

        message = EmailMessage()
        message["From"] = f"{config.FROM_NAME} <{config.FROM_EMAIL}>"
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body, subtype="html")

        await aiosmtplib.send(
            message,
            hostname=config.SMTP_HOST,
            port=config.SMTP_PORT,
            username=config.SMTP_USERNAME,
            password=config.SMTP_PASSWORD,
            start_tls=True,
        )
        return {"token": token, "link": magic_link}

    else:
        subject = "Notification from YourApp"
        body = f"""
        <html>
          <body>
            <p>Hello,</p>
            <p>This is a notification email.</p>
          </body>
        </html>
        """

        message = EmailMessage()
        message["From"] = f"{config.FROM_NAME} <{config.FROM_EMAIL}>"
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body, subtype="html")

        await aiosmtplib.send(
            message,
            hostname=config.SMTP_HOST,
            port=config.SMTP_PORT,
            username=config.SMTP_USERNAME,
            password=config.SMTP_PASSWORD,
            start_tls=True,
        )
        return None
