import inspect
from functools import wraps
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def use_register(schema,model,field):
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            sig = inspect.signature(func)
            params = sig.parameters
            bound = sig.bind_partial(*args, **kwargs)
            
            target_param = None
            if schema:
                for name, param in params.items():
                    if param.annotation is schema:
                        target_param = name
                        break
                    
            if not target_param or target_param not in bound.arguments:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Unable to find the registration schema in your endpoint signature")

            user_data: BaseModel = bound.arguments[target_param]
            
            db: Session = bound.arguments.get("db")
            
            
            column = getattr(model, field)
            value  = getattr(user_data, field, None) 

            already = db.query(model).filter(column == value).first()
            if already:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=f"A user with that {field} already exists")
            
            payload = user_data.dict()
            if "password" in payload:
                payload["hashed_password"] = pwd_context.hash(payload.pop("password"))
            
            new_user = model(**payload)
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            
            return await func(*args,new_user=new_user, **kwargs)

        return wrapper
    
    return decorator
