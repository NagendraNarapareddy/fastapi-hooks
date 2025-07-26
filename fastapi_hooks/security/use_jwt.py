import json
import functools
from typing import Callable, Optional
from jose.constants import ALGORITHMS
from datetime import datetime, timedelta
from jose import jwt,ExpiredSignatureError
from jose.exceptions import JWTError, JWKError, JWSError
from fastapi import Request,Response,HTTPException, status


TOKEN_EXPIRE = 30


class JWTTokenError(Exception):
    pass


def generate_jwt_token( data: dict, secret_key: str, algorithm: str = "HS256", expires_delta: timedelta = None) -> str:
    
    if not data or not isinstance(data, dict):
        raise JWTTokenError("Payload 'data' must be a non-empty dictionary.")
    
    if not secret_key:
        raise JWTTokenError("Secret key must be provided.")
    
    if algorithm not in ALGORITHMS.SUPPORTED:
        raise JWTTokenError(f"Algorithm '{algorithm}' is not supported. Choose from: {', '.join(ALGORITHMS.SUPPORTED)}")

    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=TOKEN_EXPIRE))

    payload = {
        "sub": json.dumps(data),
        "iat": now,
        "exp": expire
    }

    try:
        return jwt.encode(payload, secret_key, algorithm=algorithm)
    except (JWTError, JWKError, JWSError) as e:
        raise JWTTokenError(f"JWT encoding failed: {e}")


def store_jwt_token(response:Response,token: str,max_age: int = 1800,same_site:str="strict")-> None:
    try:
        if not token or not isinstance(token, str):
            raise JWTTokenError("Token must be a non-empty string.")
    
        response.set_cookie(
            key="jwt",
            value=token,
            httponly=True,
            max_age=max_age,
            samesite=same_site,
            secure=True
        )
        
    except Exception as e:
        raise JWTTokenError(f"Failed to store JWT token in cookie: {e}")


def get_jwt_token(response: Response, data:dict,secret_key,algorithm,same_site: str = "strict"):
    
    token=generate_jwt_token(data,secret_key,algorithm)
    store_jwt_token(response,token,same_site)
    return {"jwt_token":token}


async def validate_jwt_token(request:Request,secret_key: str,algorithm):
    
    token = request.cookies.get("jwt") or request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.split(" ", 1)[1]

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Missing JWT token.")
    
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return json.loads(payload.get("sub", "{}"))
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Jwt token expired.")
    except JWTError as e:
        raise HTTPException(status_code=403, detail=f"Invalid jwt token: {e}")


def use_jwt(secret_key: str,algorithm:str="HS256"):
    
    def decorator(route_handler:Callable)->Callable:
        
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            request:Optional[Request]=None
            
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")

            if not request:
                raise JWTTokenError("No Request object found in route handler parameters.")
            
            request.state.user=await validate_jwt_token(request,secret_key,algorithm)
            
            return await route_handler(*args, **kwargs)
        
        return wrapper
    
    return decorator

