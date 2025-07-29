import time
import functools
from threading import Lock
from fastapi import Request, HTTPException
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

rate_limit_store = {}
rate_limit_lock = Lock()

def get_time_key(window_seconds: int) -> int:
    return int(time.time() // window_seconds)

def use_rate_limit(limit:int,window_seconds:int):
    def decorator(route_handler):
        @functools.wraps(route_handler)
        async def wrapper(*args, **kwargs):
            request: Request = None
            for arg in list(args) + list(kwargs.values()):
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                raise RuntimeError("Request object not found in route dependencies")
            identifier=request.client.host
            time_key = get_time_key(window_seconds)
            key=f"{identifier}:{time_key}"
            
            with rate_limit_lock:
                count,expiry=rate_limit_store.get(key, (0, time.time() + window_seconds))
                if count>=limit:
                    raise HTTPException(status_code=HTTP_429_TOO_MANY_REQUESTS,detail="Rate limit exceeded")
                rate_limit_store[key] = (count + 1, expiry)
            return await route_handler(*args, **kwargs)
        
        return wrapper
    
    return decorator
