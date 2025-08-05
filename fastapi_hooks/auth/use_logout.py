import functools
from typing import Callable, Optional
from fastapi import Request, Response
from fastapi_hooks.security.use_jwt import validate_jwt_token, JWTTokenError


def use_logout(secret_key: str, algorithm: str = "HS256", same_site: str = "strict") -> Callable:

    def decorator(route_handler: Callable) -> Callable:
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            request: Optional[Request] = None
            response: Optional[Response] = None

            # Extract Request and Response objects from args/kwargs
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

            # Ensure token is valid or refreshable
            await validate_jwt_token(request, response, secret_key, algorithm)

            # Clear the refresh token cookie
            response.delete_cookie(
                key="refresh_token",
                samesite=same_site,
                secure=True
            )

            return await route_handler(*args, **kwargs)

        return wrapper

    return decorator
