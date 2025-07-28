import time
from threading import Lock
from typing import Callable, Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

_rate_limit_store = {}
_rate_limit_lock = Lock()

def get_time_key(window_seconds: int) -> int:
    return int(time.time() // window_seconds)


print(get_time_key(60))
