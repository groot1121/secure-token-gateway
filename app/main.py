from dotenv import load_dotenv
load_dotenv()

import uuid
import time
import base64
import os

from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ================= RATE LIMIT =================
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.rate_limit import limiter

# ================= REPLAY =================
from app.replay_guard import (
    check_and_mark_jti,
    check_and_mark_signature,
)

# ================= AUTH =================
from app.auth_utils import (
    generate_token,
    verify_jwt,
    verify_pop_signature,
)

from app.key_manager import generate_rsa_keys
from app.data_store import revoked_tokens   # ✅ SINGLE SOURCE

# ================= AUDIT =================
from app.audit_logger import log_event

# ================= APP =================
app = FastAPI(title="Secure Token Gateway")
security = HTTPBearer()

# ================= ADMIN =================
from app.admin_routes import router as admin_router
app.include_router(admin_router)

# ================= RATE LIMIT =================
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests"},
    )

# ================= STARTUP =================
@app.on_event("startup")
def startup():
    generate_rsa_keys()

# ================= DEV STATE =================
registered_devices: dict[str, dict[str, str]] = {}
challenges: dict[str, dict] = {}

CHALLENGE_TTL_SECONDS = 60

# ================= CORS =================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= ROUTES =================

@app.post("/register-device")
def register_device(user_id: str, device_id: str, public_key: str):
    registered_devices.setdefault(user_id, {})
    registered_devices[user_id][device_id] = public_key
    log_event(user_id, device_id, "REGISTER_DEVICE", "SUCCESS")
    return {"status": "registered"}

@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    if user_id not in registered_devices:
        raise HTTPException(403, "user not registered")
    if device_id not in registered_devices[user_id]:
        raise HTTPException(403, "device not registered")

    token = generate_token(
        user_id,
        device_id,
        registered_devices[user_id][device_id],
    )

    log_event(user_id, device_id, "ISSUE_TOKEN", "SUCCESS")
    return {"access_token": token}

@app.get("/protected")
def protected(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(security),
    x_pop_signature: str = Header(..., alias="X-Pop-Signature"),
):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(401, "invalid token")

    if payload["jti"] in revoked_tokens:
        raise HTTPException(401, "revoked token")

    if check_and_mark_jti(payload["jti"]):
        log_event(payload["sub"], payload["device_id"], "ACCESS_DENIED", "REPLAY_JTI")
        raise HTTPException(403, "replay detected")

    if check_and_mark_signature(x_pop_signature):
        log_event(payload["sub"], payload["device_id"], "ACCESS_DENIED", "REPLAY_SIGNATURE")
        raise HTTPException(403, "signature replay")

    message = f"ACCESS:{payload['jti']}".encode()
    public_key = payload["cnf"]["pk"]

    if not verify_pop_signature(message, x_pop_signature, public_key):
        log_event(payload["sub"], payload["device_id"], "ACCESS_DENIED", "BAD_SIGNATURE")
        raise HTTPException(403, "bad signature")

    log_event(
        payload["sub"],
        payload["device_id"],
        "ACCESS_GRANTED",
        "SUCCESS",
        payload={"path": request.url.path},
    )

    return {"message": "access granted"}
