from functools import wraps
from fastapi import Response
from fastapi.responses import JSONResponse
from typing import Callable, Optional


DEFAULT_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'"
}

def use_secure_headers(custom_headers: Optional[dict] = None) -> Callable:
    
    headers = {**DEFAULT_HEADERS, **(custom_headers or {})}

    def decorator(route_handler):
        @wraps(route_handler)
        async def wrapper(*args, **kwargs) -> Response:
            
            result = await route_handler(*args, **kwargs)

            if isinstance(result, Response):
                response = result
            else:
                response = JSONResponse(content=result)

            # Apply secure headers
            for key, value in headers.items():
                response.headers[key] = value

            return response

        return wrapper

    return decorator
