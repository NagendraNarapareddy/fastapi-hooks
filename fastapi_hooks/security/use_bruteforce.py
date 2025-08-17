import time
from functools import wraps
from fastapi import Request, HTTPException

failed_attempts = {}

def use_bruteforce(max_attempts=5, window_seconds=60):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            client_ip = request.client.host if request else "unknown"

            now = time.time()
            user_attempts = failed_attempts.get(client_ip, [])

            # keep only recent failed attempts
            user_attempts = [t for t in user_attempts if now - t < window_seconds]

            if len(user_attempts) >= max_attempts:
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts. Try again later."
                )

            try:
                result = await func(*args, **kwargs)

                # if login success → clear failed attempts for that IP
                if getattr(result, "status_code", 200) == 200:
                    failed_attempts[client_ip] = []
                return result

            except HTTPException as e:
                # only count failed login (like 401/403)
                if e.status_code in (401, 403):
                    user_attempts.append(now)
                    failed_attempts[client_ip] = user_attempts
                raise e
        return wrapper
    return decorator
