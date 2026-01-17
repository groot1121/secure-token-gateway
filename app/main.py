from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import uuid, time, base64, os

from app.auth_utils import (
    generate_token,
    verify_jwt,
    verify_pop_signature,
)
from app.key_manager import generate_rsa_keys
from app.audit_logger import init_audit_logger, log_event

# ---------------- APP ----------------

app = FastAPI(title="Secure Token Gateway")
security = HTTPBearer()

# ---------------- STARTUP ----------------

@app.on_event("startup")
def startup():
    generate_rsa_keys()
    init_audit_logger()

# ---------------- STATE (DEV ONLY) ----------------
# TODO: Move to Redis / Mongo

registered_devices: dict[str, dict[str, str]] = {}
challenges: dict[str, dict] = {}
revoked_tokens: set[str] = set()

CHALLENGE_TTL_SECONDS = 60

# ---------------- CORS ----------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DEVICE REGISTRATION ----------------

@app.post("/register-device")
def register_device(user_id: str, device_id: str, public_key: str):
    registered_devices.setdefault(user_id, {})
    registered_devices[user_id][device_id] = public_key

    log_event(user_id, device_id, "REGISTER_DEVICE", "SUCCESS")
    return {"status": "registered"}

# ---------------- TOKEN ISSUE ----------------

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

# ---------------- PROTECTED ----------------

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

    # 🔒 FROZEN CANONICAL MESSAGE (DO NOT CHANGE)
    message = f"ACCESS:{payload['jti']}".encode("utf-8")

    signature = base64.b64decode(x_pop_signature)
    public_key = payload["cnf"]["pk"]

    if not verify_pop_signature(message, signature, public_key):
        log_event(
            payload["sub"],
            payload["device_id"],
            "ACCESS_DENIED",
            "BAD_SIGNATURE",
        )
        raise HTTPException(403, "bad signature")

    log_event(
        payload["sub"],
        payload["device_id"],
        "ACCESS_GRANTED",
        "SUCCESS",
        payload={
            "jti": payload["jti"],
            "path": request.url.path,
            "method": request.method,
        },
    )
    return {"message": "access granted"}

# ---------------- CHALLENGE ----------------

@app.get("/challenge")
def challenge():
    cid = str(uuid.uuid4())
    nonce = base64.b64encode(os.urandom(32)).decode()

    challenges[cid] = {
        "nonce": nonce,
        "used": False,
        "ts": time.time(),
    }

    log_event("system", "n/a", "CHALLENGE_ISSUED", "SUCCESS")
    return {"challenge_id": cid, "nonce": nonce}

# ---------------- CHALLENGE VERIFY ----------------

@app.post("/challenge-verify")
def challenge_verify(
    challenge_id: str,
    signature: str,
    user_id: str,
    device_id: str,
):
    challenge = challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(401, "invalid challenge")

    if challenge["used"]:
        raise HTTPException(403, "challenge already used")

    if time.time() - challenge["ts"] > CHALLENGE_TTL_SECONDS:
        raise HTTPException(403, "challenge expired")

    if user_id not in registered_devices:
        raise HTTPException(403, "unknown user")

    if device_id not in registered_devices[user_id]:
        raise HTTPException(403, "unknown device")

    # 🔒 FROZEN CANONICAL MESSAGE
    message = f"CHALLENGE:{challenge_id}:{challenge['nonce']}".encode("utf-8")

    sig = base64.b64decode(signature)
    pub = registered_devices[user_id][device_id]

    if not verify_pop_signature(message, sig, pub):
        log_event(user_id, device_id, "CHALLENGE_FAILED", "BAD_SIGNATURE")
        raise HTTPException(403, "bad challenge signature")

    challenge["used"] = True
    log_event(user_id, device_id, "CHALLENGE_VERIFIED", "SUCCESS")
    return {"status": "challenge verified"}

# ---------------- ROTATE ----------------

@app.post("/rotate-token")
def rotate(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(401, "invalid token")

    revoked_tokens.add(payload["jti"])

    new_token = generate_token(
        payload["sub"],
        payload["device_id"],
        payload["cnf"]["pk"],
    )

    log_event(payload["sub"], payload["device_id"], "ROTATE_TOKEN", "SUCCESS")
    return {"access_token": new_token}
