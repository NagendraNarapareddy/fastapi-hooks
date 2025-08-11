import secrets
import inspect
import functools
from typing import Callable
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from pydantic import BaseModel

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

RESET_TOKEN_EXPIRE_MINUTES = 30
RESET_TOKEN_LENGTH = 32

def generate_reset_token() -> str:
    return secrets.token_urlsafe(RESET_TOKEN_LENGTH)

def send_reset_email(email: str, token: str) -> None:
    # Replace with actual email logic
    print(f"Password reset token for {email}: {token}")

def use_password_reset(model, email_field: str = "email", password_field: str = "hashed_password"):
    """
    Decorator to handle password reset flows without enforcing fixed Pydantic models.
    Will check developer-provided schema dynamically for required fields.
    """
    def decorator(route_handler: Callable) -> Callable:
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            try:
                # Detect request data from handler parameters
                sig = inspect.signature(route_handler)
                bound = sig.bind_partial(*args, **kwargs)
                request_data = None

                for name, param in sig.parameters.items():
                    if inspect.isclass(param.annotation) and issubclass(param.annotation, BaseModel):
                        request_data = bound.arguments.get(name)
                        if request_data:
                            break

                if not request_data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Missing request data"
                    )

                # Database session must be provided
                db: Session = bound.arguments.get("db")
                if not isinstance(db, Session):
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Database session not provided or invalid"
                    )

                # Convert Pydantic model to dict for dynamic field checking
                data_dict = request_data.dict()

                # --- Flow 1: Password Reset Request (must have email) ---
                if email_field in data_dict and "token" not in data_dict:
                    email = data_dict[email_field]
                    column = getattr(model, email_field)
                    user = db.query(model).filter(column == email).first()

                    if user:
                        reset_token = generate_reset_token()
                        expires_at = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
                        
                        setattr(user, "reset_token", reset_token)
                        setattr(user, "reset_token_expires", expires_at)
                        db.commit()

                        send_reset_email(email, reset_token)
                        return {"message": "A reset link has been sent"}

                    return {"message": "User not found"}

                # --- Flow 2: Password Reset Confirm (must have token + new passwords) ---
                elif "token" in data_dict:
                    token = data_dict.get("token")
                    new_password = data_dict.get("new_password")
                    confirm_password = data_dict.get("confirm_password")

                    if not token or not new_password or not confirm_password:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Missing required fields for password reset confirmation"
                        )

                    if new_password != confirm_password:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Passwords do not match"
                        )

                    user = db.query(model).filter(
                        model.reset_token == token,
                        model.reset_token_expires > datetime.utcnow()
                    ).first()

                    if not user:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid or expired reset token"
                        )

                    setattr(user, password_field, pwd_context.hash(new_password))
                    setattr(user, "reset_token", None)
                    setattr(user, "reset_token_expires", None)
                    db.commit()

                    return {"message": "Password updated successfully"}

                # --- Invalid request type ---
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid request data type"
                    )

            except HTTPException:
                raise
            except Exception as e:
                print(f"Password reset error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Password reset processing failed"
                )

        return wrapper
    return decorator
