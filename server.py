from fastapi import FastAPI, Request, Response
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import JSONResponse
from fastapi_hooks.security.use_csrf import get_csrf_token, use_csrf 

app = FastAPI()

# Enable session middleware
app.add_middleware(SessionMiddleware, secret_key="ascmaksnckancknask@2yueh18y")

@app.get("/csrf-token")
async def csrf_token(request: Request,response:Response):
    token_data = get_csrf_token(request, response)
    return {"message":token_data}

@app.post("/secure")
@use_csrf()
async def secured_endpoint(request: Request):
    return {"message": "CSRF passed"}
