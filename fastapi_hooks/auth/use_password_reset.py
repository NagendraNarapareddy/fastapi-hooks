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

class PasswordResetRequest(BaseModel):
    email: str

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    confirm_password: str

def generate_reset_token() -> str:
    return secrets.token_urlsafe(RESET_TOKEN_LENGTH)

def send_reset_email(email: str, token: str) -> None:
    print(f"Password reset token for {email}: {token}") 

def use_password_reset(model, email_field: str = "email", password_field: str = "hashed_password"):
    def decorator(route_handler: Callable) -> Callable:
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            try:
                sig = inspect.signature(route_handler)
                params = sig.parameters
                bound = sig.bind_partial(*args, **kwargs)

                request_data = None
                for name, param in params.items():
                    if issubclass(param.annotation, BaseModel):
                        request_data = bound.arguments.get(name)
                        if request_data:
                            break

                if not request_data:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Missing request data")

                db: Session = bound.arguments.get("db")
                if not isinstance(db, Session):
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail="Database session not provided or invalid")

                if isinstance(request_data, PasswordResetRequest):
                    email = getattr(request_data, email_field)
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
                    return {"message":"User not found"}

                elif isinstance(request_data, PasswordResetConfirm):
                    if request_data.new_password != request_data.confirm_password:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Passwords do not match")

                    user = db.query(model).filter(model.reset_token == request_data.token,model.reset_token_expires > datetime.utcnow()).first()

                    if not user:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid or expired reset token")

                    setattr(user, password_field, pwd_context.hash(request_data.new_password))
                    setattr(user, "reset_token", None)
                    setattr(user, "reset_token_expires", None)
                    db.commit()

                    return {"message": "Password updated successfully"}

                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Invalid request data type")

            except HTTPException:
                raise
            except Exception as e:
                print(f"Password reset error: {e}")
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail="Password reset processing failed")

        return wrapper
    return decorator