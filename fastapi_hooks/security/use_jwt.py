import json
import functools
from typing import Callable, Optional
from jose.constants import ALGORITHMS
from datetime import datetime, timedelta
from jose import jwt,ExpiredSignatureError
from fastapi import Request,Response,HTTPException
from jose.exceptions import JWTError, JWKError, JWSError


TOKEN_EXPIRE = 15


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


def store_jwt_token(response:Response,token: str,same_site:str)-> None:
    try:
        if not token or not isinstance(token, str):
            raise JWTTokenError("Token must be a non-empty string.")
    
        response.set_cookie(
            key="refresh_token",
            value=token,
            httponly=True,
            max_age=timedelta(days=7).total_seconds(),
            samesite=same_site,
            secure=True
        )
        
    except Exception as e:
        raise JWTTokenError(f"Failed to store JWT token in cookie: {e}")


def get_jwt_token(response: Response, data:dict,secret_key:str,algorithm:str,same_site: str = "strict"):
    
    access_token=generate_jwt_token(data,secret_key,algorithm)
    
    refresh_token=generate_jwt_token(data,secret_key,algorithm,expires_delta=timedelta(days=7))
    
    store_jwt_token(response,refresh_token,same_site)
    
    
    return {
        "access_token":access_token,
        "token_type":"bearer"
        }


async def validate_jwt_token(request: Request,response: Response,secret_key: str,algorithm: str):

    token = None
    user_payload = None

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        raise HTTPException(status_code=401, detail="Missing access token.")
    
    if token:
        try:
            payload = jwt.decode(token, secret_key, algorithms=[algorithm])
            return json.loads(payload.get("sub", "{}")) 
        except ExpiredSignatureError:
            pass 
        except JWTError as e:
            raise HTTPException(status_code=403, detail=f"Invalid access token: {e}")

    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token. Please login again.")

    try:
        payload = jwt.decode(refresh_token, secret_key, algorithms=[algorithm])
        user_payload = json.loads(payload.get("sub", "{}"))

        new_access_token = generate_jwt_token(data=user_payload,secret_key=secret_key,algorithm=algorithm)

        response.headers["X-New-Access-Token"] = new_access_token

        return user_payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired. Please login again.")
    except JWTError as e:
        raise HTTPException(status_code=403, detail=f"Invalid refresh token: {e}")


def use_jwt(secret_key: str,algorithm:str="HS256"):
    
    def decorator(route_handler:Callable)->Callable:
        
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            request:Optional[Request]=None
            response: Optional[Response] = None
            
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                elif isinstance(arg, Response):
                    response = arg
                    
            if not request:
                request = kwargs.get("request")
            
            if not response:
                response = kwargs.get("response")

            if not request or not response:
                raise JWTTokenError("Request or Response object not found in route handler parameters.")

            request.state.user=await validate_jwt_token(request,response,secret_key,algorithm)
            
            return await route_handler(*args, **kwargs)
        
        return wrapper
    
    return decorator

