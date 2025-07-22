import secrets
import functools
from typing import Callable, Optional
from fastapi import HTTPException, Request, Response
from starlette.middleware.sessions import SessionMiddleware


# CSRF token key for session and header
CSRF_TOKEN_KEY = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

def generate_csrf_token() -> str:
    """
    Generate a cryptographically secure CSRF token.
    
    Returns:
        str: A URL-safe token of 32 bytes.
    """
    return secrets.token_urlsafe(32)


def store_csrf_token(request: Request, response: Response, token: str) -> None:
    """
    Store a CSRF token in the session and set a secure cookie.

    Args:
        request: FastAPI Request object to access session.
        response: FastAPI Response object to set the cookie.
        token: The CSRF token to store.

    Raises:
        HTTPException: If SessionMiddleware is not configured.
    """
    # Check for SessionMiddleware
    if not hasattr(request.app, "middleware") or not any(isinstance(m, SessionMiddleware) for m in request.app.middleware_stack.middleware):
        raise HTTPException(status_code=500,detail="SessionMiddleware required for CSRF token storage. Add it to your FastAPI app.")

    # Store token in session
    request.session[CSRF_TOKEN_KEY] = token

    # Set secure cookie
    response.set_cookie(
        key=CSRF_TOKEN_KEY,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
    )


def get_csrf_token(request: Request, response: Response) -> dict:
    """
    Generate and store a CSRF token, returning it for frontend use.

    Args:
        request: FastAPI Request object to access session.
        response: FastAPI Response object to set the cookie.

    Returns:
        dict: JSON response with the CSRF token (e.g., {"csrf_token": "..."}).
    """
    token = generate_csrf_token()
    store_csrf_token(request, response, token)
    return {"csrf_token": token}

    
async def validate_csrf_token(request: Request, session_token: str) -> None:
    """
    Validate the client-submitted CSRF token against the session token.

    Args:
        request: FastAPI Request object to access headers, form, or JSON.
        session_token: The CSRF token stored in the session.

    Raises:
        InvalidCSRFTokenError: If the token is missing or invalid.
    """
    submitted_token = request.headers.get(CSRF_HEADER)
    
    if not submitted_token and request.headers.get("content-type", "").startswith("multipart/form-data"):
        form = await request.form()
        submitted_token = form.get(CSRF_TOKEN_KEY)
    elif not submitted_token and request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
        submitted_token = body.get(CSRF_TOKEN_KEY)

    if not submitted_token or not secrets.compare_digest(submitted_token, session_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def use_csrf() -> Callable:
    """
    Decorator to validate CSRF token from request headers/form/json.

    Returns:
        Callable: Decorated route function.
    """
    def decorator(route_handler: Callable) -> Callable:
        @functools.wraps(route_handler)
        async def async_wrapper(*args, **kwargs):
            request: Optional[Request] = None

            # Extract the request object from args or kwargs
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")

            if not request:
                raise RuntimeError("No Request object found in route handler parameters")

            session_token = request.session.get(CSRF_TOKEN_KEY)
            await validate_csrf_token(request, session_token)

            return await route_handler(*args, **kwargs)

        return async_wrapper

    return decorator