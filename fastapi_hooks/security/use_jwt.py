from datetime import datetime, timedelta
from jose import jwt, JWTError
from jose.constants import ALGORITHMS

ALGORITHM = "HS256"
TOKEN_EXPIRE = 30


class JWTTokenError(Exception):
    """Raised when JWT token generation fails or input is invalid."""
    pass


def generate_token( data: dict, secret_key: str, algorithm: str = ALGORITHM, expires_delta: timedelta = None) -> str:
    
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

