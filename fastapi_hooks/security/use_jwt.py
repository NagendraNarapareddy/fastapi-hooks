from datetime import datetime, timedelta
from jose import jwt

# Configuration
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict,  secret_key: str = SECRET_KEY,algorithm: str=ALGORITHM,expires_delta: timedelta = None):
    now = datetime.utcnow()

    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": data,
        "iat": now,
        "exp": expire,
    }

    encoded_jwt = jwt.encode(payload, secret_key, algorithm=algorithm)
    
    return encoded_jwt

