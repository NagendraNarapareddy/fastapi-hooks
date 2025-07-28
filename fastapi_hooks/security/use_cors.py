import functools
from fastapi import Response,Request
from typing import Optional

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


def set_cors_headers(request: Request, response: Response, policy: dict):
    
    origins = normalize(policy.get("allow_origins"))
    methods = normalize(policy.get("allow_methods"))
    headers = normalize(policy.get("allow_headers"))
    expose  = normalize(policy.get("expose_headers"))

    # Origin
    if origins:
        if origins == ["*"]:
            response.headers["Access-Control-Allow-Origin"] = "*"
        else:
            origin = request.headers.get("origin")
            if origin in origins:
                response.headers["Access-Control-Allow-Origin"] = origin

    # Methods (reflect on wildcard)
    if methods:
        if methods == ["*"]:
            req_method = request.headers.get("access-control-request-method")
            if req_method:
                response.headers["Access-Control-Allow-Methods"] = req_method
        else:
            response.headers["Access-Control-Allow-Methods"] = ",".join(methods)

    # Headers (reflect on wildcard)
    if headers:
        if headers == ["*"]:
            req_hdrs = request.headers.get("access-control-request-headers")
            if req_hdrs:
                response.headers["Access-Control-Allow-Headers"] = req_hdrs
        else:
            response.headers["Access-Control-Allow-Headers"] = ",".join(headers)

    # Credentials
    if policy.get("allow_credentials"):
        response.headers["Access-Control-Allow-Credentials"] = "true"

    # Expose headers
    if expose:
        response.headers["Access-Control-Expose-Headers"] = ",".join(expose)

    # Max age
    if policy.get("max_age") is not None:
        response.headers["Access-Control-Max-Age"] = str(policy.get("max_age"))


async def preflight(request: Request,policy:dict):
    response=Response(status_code=204)
    set_cors_headers(request,response, policy)
    return response
    

def use_cors(preset_or_kwargs="public", **kwargs):
    if isinstance(preset_or_kwargs, str):
        policy = cors_presets[preset_or_kwargs]
    else:
        policy = preset_or_kwargs

    if kwargs:
        policy = {**policy, **kwargs} 
    
    if not policy.get("allow_origins"):
        raise ValueError("CORS policy must define non-empty 'allow_origins'. Set it explicitly when using @use_cors().")

    def decorator(route_handler):
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
            
            if not response or not request:
                raise RuntimeError("Request or Response object not found in route handler parameters.")
            
            result = await route_handler(*args, **kwargs)
            set_cors_headers(request,response, policy)
            return result

        return wrapper

    return decorator
