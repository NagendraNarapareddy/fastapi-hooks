import aiosmtplib
from email.message import EmailMessage

async def send_email(config: dict, to_email: str, body: str,subject:str) -> None:
    subject = subject
    
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


