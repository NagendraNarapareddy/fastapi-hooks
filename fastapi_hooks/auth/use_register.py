import inspect
from functools import wraps
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from passlib.context import CryptContext
from fastapi import HTTPException, status

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def use_register(schema, model, field):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                sig = inspect.signature(func)
                params = sig.parameters
                bound = sig.bind_partial(*args, **kwargs)

                # Find the parameter matching the schema annotation
                target_param = None
                if schema:
                    for name, param in params.items():
                        if param.annotation is schema:
                            target_param = name
                            break

                if not target_param or target_param not in bound.arguments:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Unable to find the registration schema in your endpoint signature"
                    )

                # Extract the Pydantic data and DB session
                user_data: BaseModel = bound.arguments[target_param]
                db: Session = bound.arguments.get("db")
                if not isinstance(db, Session):
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Database session not provided or invalid"
                    )

                # Check uniqueness
                column = getattr(model, field)
                value = getattr(user_data, field, None)
                if value is None:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Missing required field '{field}'"
                    )

                existing = db.query(model).filter(column == value).first()
                if existing:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"A user with that {field} already exists"
                    )

                # Prepare payload and hash password
                payload = user_data.dict()
                if "password" in payload:
                    payload["hashed_password"] = pwd_context.hash(payload.pop("password"))

                # Create and persist new user
                new_user = model(**payload)
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                
                kwargs['new_user'] = new_user

                result=await func(*args,**kwargs)
                return result
                
            except HTTPException:
                raise
            except IntegrityError as ie:
                db.rollback()
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Database integrity error: possibly duplicate or invalid data")
            except SQLAlchemyError as se:
                db.rollback()
                print(se)
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail="Internal database error")
            except Exception as e:
                print(e)
                raise HTTPException( status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected server error")

        return wrapper

    return decorator
