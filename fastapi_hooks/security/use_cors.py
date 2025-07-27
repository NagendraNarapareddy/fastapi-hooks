import functools
from fastapi import Response,Request


cors_presets = {
    # 1. Public read-only APIs
    "public": {
        "allow_origins": [],
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
        "allow_credentials": False
    },

    # 2. Local development frontend
    "dev": {
        "allow_origins": [],
        "allow_methods": ["*"],
        "allow_headers": ["*"],
        "allow_credentials": True
    },

    # 3. Authenticated routes with cookies
    "auth": {
        "allow_origins": [],
        "allow_methods": ["POST"],
        "allow_headers": ["Authorization", "Content-Type"],
        "allow_credentials": True
    },

    # 4. Admin dashboard
    "admin": {
        "allow_origins": [],
        "allow_methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
        "allow_credentials": True,
        "max_age": 600
    },

    # 5. External partner integration
    "partner": {
        "allow_origins": [],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["Authorization", "X-Custom-Header"],
        "allow_credentials": True
    },

    # 6. Trusted CDN assets
    "cdn": {
        "allow_origins": [],
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
        "allow_credentials": False,
        "max_age": 3600
    },

    # 7. Secure file uploads (from same origin)
    "upload": {
        "allow_origins": [],
        "allow_methods": ["POST"],
        "allow_headers": ["Authorization", "Content-Type"],
        "allow_credentials": True
    },

    # 8. Developer playground (e.g., GraphQL, Swagger)
    "playground": {
        "allow_origins": [],
        "allow_methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["*"],
        "allow_credentials": False
    },

    # 9. Customer support tools
    "support": {
        "allow_origins": [],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["Authorization", "Content-Type"],
        "allow_credentials": True
    },

    # 10. Internal microservices
    "internal": {
        "allow_origins": [],
        "allow_methods": ["*"],
        "allow_headers": ["*"],
        "allow_credentials": True
    },
}


def normalize(value):
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


def set_cors_headers(response, policy):

    origins = normalize(policy.get("allow_origins"))
    methods = normalize(policy.get("allow_methods"))
    headers = normalize(policy.get("allow_headers"))
    expose  = normalize(policy.get("expose_headers"))

    if origins:
        response.headers["Access-Control-Allow-Origin"] = ",".join(origins)
    if methods:
        response.headers["Access-Control-Allow-Methods"] = ",".join(methods)
    if headers:
        response.headers["Access-Control-Allow-Headers"] = ",".join(headers)
    if policy.get("allow_credentials"):
        response.headers["Access-Control-Allow-Credentials"] = "true"
    if expose:
        response.headers["Access-Control-Expose-Headers"] = ",".join(expose)
    if policy.get("max_age") is not None:
        response.headers["Access-Control-Max-Age"] = str(policy.get("max_age"))


async def preflight(request: Request, response: Response):
    
    set_cors_headers(response, policy=None)
    return Response(status_code=204)


def use_cors(preset_or_kwargs="public", **kwargs):
    if isinstance(preset_or_kwargs, str):
        policy = cors_presets[preset_or_kwargs]
    else:
        policy = preset_or_kwargs

    if kwargs:
        policy = {**policy, **kwargs} 

    def decorator(route_handler):
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs_inner):
            response = kwargs_inner.get("response")
            if not response:
                for arg in args:
                    if isinstance(arg, Response):
                        response = arg
                        break
            if not response:
                raise RuntimeError("Handler must accept a `response: Response`")
            result = await route_handler(*args, **kwargs_inner)
            set_cors_headers(response, policy)
            return result

        return wrapper

    return decorator
