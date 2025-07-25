from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import Request,Response
from jose.constants import ALGORITHMS

ALGORITHM = "HS256"
TOKEN_EXPIRE = 30


class JWTTokenError(Exception):
    """Raised when JWT token generation fails or input is invalid."""
    pass


def generate_jwt_token( data: dict, secret_key: str, algorithm: str = ALGORITHM, expires_delta: timedelta = None) -> str:
    
    if not data or not isinstance(data, dict):
        raise JWTTokenError("Payload 'data' must be a non-empty dictionary.")
    
    if not secret_key:
        raise JWTTokenError("Secret key must be provided.")
    
    if algorithm not in ALGORITHMS.SUPPORTED:
        raise JWTTokenError(f"Algorithm '{algorithm}' is not supported. Choose from: {', '.join(ALGORITHMS.SUPPORTED)}")

    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=TOKEN_EXPIRE))

    payload = {
        "sub": data,
        "iat": now,
        "exp": expire
    }

    try:
        return jwt.encode(payload, secret_key, algorithm=algorithm)
    except JWTError as e:
        raise JWTTokenError(f"JWT encoding failed: {e}")

def store_jwt_token(request:Request,response:Response,token: str,max_age: int = 1800)-> None:
    try:
        if not token or not isinstance(token, str):
            raise JWTTokenError("Token must be a non-empty string.")
    
        response.set_cookie(
            key="jwt",
            value=token,
            httponly=True,
            max_age=max_age,
            samesite="Lax",
            secure=True
        )
        
    except Exception as e:
        raise JWTTokenError(f"Failed to store JWT token in cookie: {e}")

def get_jwt_token(request: Request, response: Response, data:dict)->str:
    
    token=generate_jwt_token()
    store_jwt_token(request,response,data)
    return {"jwt_token":token}


