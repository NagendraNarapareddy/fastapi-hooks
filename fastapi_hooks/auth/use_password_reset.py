import functools
import inspect
from typing import Callable
from pydantic import BaseModel
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from sqlalchemy.exc import SQLAlchemyError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def use_password_reset(schema, model, password_field: str):
    def decorator(route_handler: Callable) -> Callable:
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            sig = inspect.signature(route_handler)
            bound = sig.bind_partial(*args, **kwargs)
            params = sig.parameters

            target_param = None
            if schema:
                for name, param in params.items():
                    if param.annotation is schema:
                        target_param = name
                        break

            if not target_param or target_param not in bound.arguments:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unable to find the password reset schema in your endpoint signature"
                )

            reset_data: BaseModel = bound.arguments[target_param]
            db: Session = bound.arguments.get("db")
            if not isinstance(db, Session):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session not provided or invalid"
                )

            # Identify the user by a unique field in the schema (e.g., email)
            unique_fields = {k: v for k, v in reset_data.dict().items() if k != "password"}
            user = db.query(model).filter_by(**unique_fields).first()

            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Update password
            new_password = getattr(reset_data, "password", None)
            if not new_password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password field is required"
                )

            setattr(user, password_field, pwd_context.hash(new_password))

            try:
                db.add(user)
                db.commit()
                db.refresh(user)
            except SQLAlchemyError as e:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database error while resetting password"
                )

            kwargs["user"] = user
            return await route_handler(*args, **kwargs)

        return wrapper
    return decorator
