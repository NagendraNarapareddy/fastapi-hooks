import functools
import inspect
from pydantic import BaseModel
from typing import Callable,Type
from fastapi import Request, Response, HTTPException, Depends,status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi_hooks.security.use_jwt import get_jwt_token

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def use_login(schema,model,field):
    def decorator(route_handler: Callable) -> Callable:
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            sig = inspect.signature(route_handler)
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
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Unable to find the Login schema in your endpoint signature")
           
            response=bound.arguments["response"]
            
            login_data: BaseModel = bound.arguments[target_param]
            db: Session = bound.arguments.get("db")
            if not isinstance(db, Session):
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail="Database session not provided or invalid")

            column = getattr(model, field)
            value = getattr(login_data, field, None)
            
            if value is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail=f"Missing required field '{field}'")

            user = db.query(model).filter(column == value).first()
            
            if not user:
                raise HTTPException(status_code=401, detail="Invalid credentials.")

            if not pwd_context.verify(login_data.password, user.hashed_password):
                raise HTTPException(status_code=401, detail="Invalid credentials.")
            
            data={"user_id":user.id}
            
            token=get_jwt_token(response,data,"1234","HS256")
            
            kwargs["token"]=token
            
            return await route_handler(*args,**kwargs)

        return wrapper

    return decorator

