from dotenv import load_dotenv
load_dotenv()
import json
import base64
import secrets
import asyncio
from typing import List

from app.geoip_utils import get_geo

from pydantic import BaseModel
from fastapi import (
    FastAPI,
    Depends,
    Header,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    Body,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.rate_limit import limiter

from app.replay_guard import check_and_mark_jti, check_and_mark_signature
from app.auth_utils import generate_token, verify_jwt, verify_pop_signature
from app.key_manager import generate_rsa_keys
from app.audit_logger import log_event
from app.admin_routes import router as admin_router

import app.threat_engine as threat_engine
import redis

import os
from pymongo import MongoClient
from datetime import datetime

import random
import time



MONGODB_URI = os.getenv("MONGODB_URI")
MONGO_DB = os.getenv("MONGO_DB")

mongo_client = MongoClient(MONGODB_URI)
mongo_db = mongo_client[MONGO_DB]

devices_collection = mongo_db["devices"]   # new collection
audit_collection = mongo_db[os.getenv("MONGO_COLLECTION")]  # existing


# ================= REDIS =================

redis_client = redis.Redis(
    host="localhost",
    port=6379,
    db=0,
    decode_responses=True
)


# ==================Dynamic rotation==================

ROTATION_MIN = 10   # 3 minutes
ROTATION_MAX = 15   # 5 minutes

# ================= DEVICE QUARANTINE =================

def quarantine_device(user_id, device_id):

    devices_collection.update_one(
        {
            "user_id": user_id,
            "device_id": device_id
        },
        {
            "$set": {
                "status": "QUARANTINED",
                "quarantined_at": datetime.utcnow()
            }
        }
    )

# ================= JTI BLACKLIST =================

def blacklist_jti(jti, ttl=300):
    redis_client.setex(f"blacklist:jti:{jti}", ttl, "revoked")

def is_jti_blacklisted(jti):
    return redis_client.exists(f"blacklist:jti:{jti}")

# ================= APP INIT =================

app = FastAPI(title="Secure Token Gateway SOC")
security = HTTPBearer()
app.include_router(admin_router)

# ================= WEBSOCKET =================

active_connections: List[WebSocket] = []

@app.websocket("/ws/audit")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)

async def broadcast_log(log_data: dict):
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_text(json.dumps(log_data))
        except Exception:
            disconnected.append(connection)

    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)

# ================= LOG + RISK =================

async def log_and_broadcast(user_id, device_id, action, status, payload=None):
    log_event(user_id, device_id, action, status, payload=payload)

    threat_data = threat_engine.update_risk(user_id, device_id, action, status)

    # ================= AUTO DEVICE QUARANTINE =================

    if threat_data["device_threat"] == "ATTACK":
        quarantine_device(user_id, device_id)

    # ================= WEBSOCKET BROADCAST =================

    if active_connections:
        await broadcast_log({
            "user_id": user_id,
            "device_id": device_id,
            "action": action,
            "status": status,
            "payload": payload,
            "device_risk": threat_data["device_risk"],
            "device_threat": threat_data["device_threat"],
            "global_risk": threat_data["global_risk"],
            "global_threat": threat_data["global_threat"],
        })
# ================= PERIODIC GLOBAL BROADCAST =================

async def periodic_risk_broadcast():
    while True:
        await asyncio.sleep(1)

        if active_connections:
            await broadcast_log({
                "user_id": "SYSTEM",
                "device_id": "SYSTEM",
                "action": "RISK_UPDATE",
                "status": "INFO",
                "global_risk": threat_engine.get_global_risk_score(),
                "global_threat": threat_engine.get_global_threat_level(),
            })

# ================= RATE LIMIT =================

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"detail": "Too many requests"})

# ================= STARTUP =================

@app.on_event("startup")
async def startup():
    generate_rsa_keys()
    asyncio.create_task(threat_engine.risk_decay_loop())
    asyncio.create_task(periodic_risk_broadcast())

# ================= CORS =================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= REGISTER DEVICE =================


class RegisterRequest(BaseModel):
    user_id: str
    device_id: str
    public_key: str


@app.post("/register-device")
async def register_device(data: RegisterRequest):

    # 1️⃣ Store in Redis (fast runtime lookup)
    redis_client.set(
        f"device:{data.user_id}:{data.device_id}",
        data.public_key
    )

    # 2️⃣ Store in Mongo (persistent device registry)
    devices_collection.update_one(
    {
        "user_id": data.user_id,
        "device_id": data.device_id
    },
    {
        "$set": {
            "user_id": data.user_id,
            "device_id": data.device_id,
            "public_key": data.public_key,
            "registered_at": datetime.utcnow(),
            "status": "ACTIVE"
        }
    },
    upsert=True

    )

    await log_and_broadcast(
        data.user_id,
        data.device_id,
        "REGISTER_DEVICE",
        "SUCCESS"
    )

    return {"status": "registered"}


# ================= CHALLENGE =================

@app.post("/challenge")
async def challenge(user_id: str, device_id: str):
    public_key = redis_client.get(f"device:{user_id}:{device_id}")

    if not public_key:
        raise HTTPException(403, "Device not registered")

    raw_nonce = secrets.token_bytes(32)
    nonce_b64 = base64.b64encode(raw_nonce).decode()

    redis_client.setex(
        f"challenge:{user_id}:{device_id}",
        60,
        nonce_b64
    )

    await log_and_broadcast(
        user_id,
        device_id,
        "CHALLENGE_ISSUED",
        "SUCCESS"
    )

    return {"challenge": nonce_b64}

# ================= VERIFY CHALLENGE =================

class VerifyRequest(BaseModel):
    user_id: str
    device_id: str
    signature: str

@app.post("/verify-challenge")
async def verify_challenge(data: VerifyRequest):

    stored_nonce_b64 = redis_client.get(
        f"challenge:{data.user_id}:{data.device_id}"
    )

    if not stored_nonce_b64:
        raise HTTPException(403, "Challenge expired")

    raw_nonce = base64.b64decode(stored_nonce_b64)

    public_key = redis_client.get(
        f"device:{data.user_id}:{data.device_id}"
    )

    if not verify_pop_signature(raw_nonce, data.signature, public_key):
        await log_and_broadcast(
            data.user_id,
            data.device_id,
            "CHALLENGE_FAILED",
            "BAD_SIGNATURE"
        )
        raise HTTPException(403, "Invalid signature")

    redis_client.setex(
        f"verified:{data.user_id}:{data.device_id}",
        60,
        "true"
    )

    redis_client.delete(
        f"challenge:{data.user_id}:{data.device_id}"
    )

    await log_and_broadcast(
        data.user_id,
        data.device_id,
        "CHALLENGE_VERIFIED",
        "SUCCESS"
    )

    return {"status": "verified"}

# ================= ISSUE TOKEN =================

@app.post("/issue-token")
async def issue_token(user_id: str, device_id: str):

    if threat_engine.get_device_threat(user_id, device_id) in ["HIGH", "ATTACK"]:
        await log_and_broadcast(
            user_id,
            device_id,
            "TOKEN_BLOCKED",
            "RISK_THRESHOLD_EXCEEDED"
        )
        raise HTTPException(
            status_code=403,
            detail="Token issuance temporarily blocked due to elevated threat level"
        )

    verified = redis_client.get(f"verified:{user_id}:{device_id}")

    if verified != "true":
        raise HTTPException(403, "Challenge not verified")
    
    device = devices_collection.find_one(
    {"user_id": user_id, "device_id": device_id}
    )

    if device and device.get("status") == "QUARANTINED":

        await log_and_broadcast(
            user_id,
            device_id,
            "TOKEN_BLOCKED",
            "DEVICE_QUARANTINED"
        )

        raise HTTPException(
            403,
            "Device quarantined due to attack detection"
    )

    public_key = redis_client.get(f"device:{user_id}:{device_id}")

    token = generate_token(user_id, device_id, public_key)

    payload = verify_jwt(token)

    rotation_window = random.randint(ROTATION_MIN, ROTATION_MAX)

    redis_client.setex(
        f"rotate:{payload['jti']}",
        rotation_window,
        "valid"
)
    redis_client.delete(f"verified:{user_id}:{device_id}")

    await log_and_broadcast(user_id, device_id, "ISSUE_TOKEN", "SUCCESS")

    return {"access_token": token}


# ================= PROTECTED =================

@app.get("/protected")

async def protected(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(security),
    x_pop_signature: str = Header(..., alias="X-Pop-Signature"),
):


    payload = verify_jwt(creds.credentials)

    if not payload:
        raise HTTPException(401, "Invalid or expired token")

    user_id = payload["sub"]
    device_id = payload["device_id"]
    jti = payload["jti"]
    
    client_ip = request.headers.get("x-forwarded-for", request.client.host)

    geo = get_geo(client_ip)

    if geo:

        await log_and_broadcast(
        user_id,
        device_id,
        "GEO_CHECK",
        "INFO",
        payload={
            "ip": client_ip,
            "country": geo.get("country"),
            "city": geo.get("city")
        }
    )

        if geo.get("country") not in ["India"]:

            await log_and_broadcast(
            user_id,
            device_id,
            "GEO_ANOMALY",
            "WARNING",
            payload=geo
        )

        threat_engine.update_risk(
            user_id,
            device_id,
            "ACCESS_DENIED",
            "GEO_ANOMALY"
        )
    if not redis_client.exists(f"rotate:{jti}"):

        await log_and_broadcast(
            user_id,
            device_id,
            "TOKEN_EXPIRED",
            "ROTATION_REQUIRED"
            )

        raise HTTPException(
            401,
            "Token rotation required"
    )

    # ================= DEVICE STATUS CHECK =================

    device = devices_collection.find_one(
        {"user_id": user_id, "device_id": device_id}
    )

    if not device or device.get("status") != "ACTIVE":

        await log_and_broadcast(
            user_id,
            device_id,
            "ACCESS_DENIED",
            "DEVICE_QUARANTINED"
        )

        raise HTTPException(
            403,
            "Device is quarantined or blocked"
        )

    # ================= TOKEN BLACKLIST =================

    if is_jti_blacklisted(jti):
        await log_and_broadcast(
            user_id,
            device_id,
            "ACCESS_DENIED",
            "TOKEN_REVOKED"
        )
        raise HTTPException(403, "Token has been revoked")

    # ================= DEVICE THREAT CHECK =================

    device_threat = threat_engine.get_device_threat(user_id, device_id)

    if device_threat == "ATTACK":
        blacklist_jti(jti)

        await log_and_broadcast(
            user_id,
            device_id,
            "ACCESS_DENIED",
            "TOKEN_REVOKED_DUE_TO_ATTACK"
        )

        raise HTTPException(
            403,
            "Device blocked due to active attack state"
        )

    # ================= REPLAY PROTECTION =================

    jti_key = f"jti:{jti}"
    replay_key = f"replay:{jti}"

    if redis_client.exists(jti_key):

        replay_count = redis_client.incr(replay_key)

        if replay_count == 1:
            redis_client.expire(replay_key, 300)

        await log_and_broadcast(
            user_id,
            device_id,
            "ACCESS_DENIED",
            "REPLAY_JTI",
            payload={"replay_count": replay_count}
        )

        # revoke token after 10 replays
        if replay_count >= 10:

            blacklist_jti(jti)

            await log_and_broadcast(
                user_id,
                device_id,
                "TOKEN_REVOKED",
                "REPLAY_ATTACK"
            )

        raise HTTPException(403, "Replay detected")

    # mark JTI as used
    redis_client.setex(jti_key, 300, "used")

    # ================= PROOF OF POSSESSION =================

    message = f"ACCESS:{jti}".encode()

    if not verify_pop_signature(
        message,
        x_pop_signature,
        payload["cnf"]["pk"]
    ):
        await log_and_broadcast(
            user_id,
            device_id,
            "ACCESS_DENIED",
            "BAD_SIGNATURE"
        )

        raise HTTPException(403, "Invalid signature")

    # ================= SUCCESS =================

    await log_and_broadcast(
        user_id,
        device_id,
        "ACCESS_GRANTED",
        "SUCCESS",
        payload={"path": request.url.path},
    )

    return {"message": "access granted"}


# ================= ROTATE TOKEN =================

@app.post("/rotate-token")
async def rotate_token(
    creds: HTTPAuthorizationCredentials = Depends(security),
    x_pop_signature: str = Header(..., alias="X-Pop-Signature"),
):

    payload = verify_jwt(creds.credentials)

    if not payload:
        raise HTTPException(401, "Invalid token")

    user_id = payload["sub"]
    device_id = payload["device_id"]
    jti = payload["jti"]

    # verify PoP
    message = f"ROTATE:{jti}".encode()

    if not verify_pop_signature(
        message,
        x_pop_signature,
        payload["cnf"]["pk"]
    ):
        await log_and_broadcast(
            user_id,
            device_id,
            "ROTATE_DENIED",
            "BAD_SIGNATURE"
        )

        raise HTTPException(403, "Invalid signature")

    # revoke old token
    blacklist_jti(jti)
    
    # delete old rotation window
    redis_client.delete(f"rotate:{jti}")

    # issue new token
    new_token = generate_token(
        user_id,
        device_id,
        payload["cnf"]["pk"]
    )

    new_payload = verify_jwt(new_token)

    rotation_window = random.randint(ROTATION_MIN, ROTATION_MAX)

    redis_client.setex(
        f"rotate:{new_payload['jti']}",
        rotation_window,
        "valid"
    )

    await log_and_broadcast(
        user_id,
        device_id,
        "TOKEN_ROTATED",
        "SUCCESS"
    )

    return {"access_token": new_token}

# ================= ADMIN RESET =================

ADMIN_SECRET = "superadmin123"

@app.post("/admin/reset-risk")
async def reset_risk(secret: str = Body(...)):

    if secret != ADMIN_SECRET:
        raise HTTPException(403, "Unauthorized")

    threat_engine.reset_risk()

    return {"message": "Risk state reset to NORMAL"}



@app.get("/admin/devices")
async def list_devices(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(403, "Unauthorized")

    devices = list(devices_collection.find({}, {"_id": 0}))
    return {"devices": devices}


@app.get("/admin/logs")
async def get_logs(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(403, "Unauthorized")

    logs = list(audit_collection.find({}, {"_id": 0}).sort("created_at", -1).limit(100))
    return {"logs": logs}

@app.post("/admin/release-device")
async def release_device(
    user_id: str = Body(...),
    device_id: str = Body(...),
    secret: str = Body(...)
):

    if secret != ADMIN_SECRET:
        raise HTTPException(403, "Unauthorized")

    devices_collection.update_one(
        {"user_id": user_id, "device_id": device_id},
        {"$set": {"status": "ACTIVE"}}
    )

    threat_engine.reset_device_risk(user_id, device_id)

    await log_and_broadcast(
        user_id,
        device_id,
        "ADMIN_RELEASE",
        "DEVICE_RESTORED"
    )

    return {"message": "Device released"}
