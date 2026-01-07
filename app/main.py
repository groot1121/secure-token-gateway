from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uuid
import time
import base64
import os

from app.auth_utils import (
    generate_token,
    verify_jwt,
    verify_pop_signature,
)

from app.key_manager import generate_rsa_keys, generate_aes_key
from app.audit_logger import log_event

# ---------------- STATE ----------------

registered_devices = {}        # user_id -> device_id -> public_key (PEM)
challenges = {}                # challenge_id -> challenge object
revoked_tokens = set()         # revoked jti values

app = FastAPI(title="Zero‑Day Secure Token Gateway")
security = HTTPBearer()

# ---------------- STARTUP ----------------

@app.on_event("startup")
def startup():
    generate_rsa_keys()
    generate_aes_key()

# ---------------- DEVICE REGISTRATION ----------------

@app.post("/register-device")
def register_device(user_id: str, device_id: str, public_key: str):
    registered_devices.setdefault(user_id, {})
    registered_devices[user_id][device_id] = public_key

    log_event(user_id, device_id, "REGISTER_DEVICE", "SUCCESS")
    return {"message": "Device registered successfully"}

# ---------------- TOKEN ISSUANCE (FIXED) ----------------

@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    if user_id not in registered_devices:
        raise HTTPException(status_code=403, detail="User not registered")

    if device_id not in registered_devices[user_id]:
        raise HTTPException(status_code=403, detail="Device not registered")

    public_key = registered_devices[user_id][device_id]

    # NEW TOKEN ALWAYS ISSUED (no reuse)
    token = generate_token(user_id, device_id, public_key)

    log_event(user_id, device_id, "ISSUE_TOKEN", "SUCCESS")
    return {"access_token": token}

# ---------------- PROTECTED ENDPOINT ----------------

from cryptography.exceptions import InvalidSignature

@app.get("/protected")
def protected(
    creds: HTTPAuthorizationCredentials = Depends(security),
    x_pop_signature: str = Header(..., alias="X-Pop-Signature"),
):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    jti = payload["jti"]
    if jti in revoked_tokens:
        raise HTTPException(status_code=401, detail="Token revoked")

    try:
        message = b"GET:/protected"
        signature = base64.b64decode(x_pop_signature)
        public_key = payload["cnf"]["pk"]

        if not verify_pop_signature(message, signature, public_key):
            raise HTTPException(status_code=403, detail="Invalid PoP signature")

    except Exception:
        raise HTTPException(status_code=403, detail="Invalid PoP signature")

    return {"message": "Access granted"}



# @app.get("/protected")
# def protected(
#     creds: HTTPAuthorizationCredentials = Depends(security),
#     x_pop_signature: str = Header(..., alias="X-Pop-Signature"),
# ):
#     payload = verify_jwt(creds.credentials)
#     if not payload:
#         raise HTTPException(status_code=401, detail="Invalid token")

#     jti = payload["jti"]
#     if jti in revoked_tokens:
#         raise HTTPException(status_code=401, detail="Token revoked")

#     message = b"GET:/protected"
#     signature = base64.b64decode(x_pop_signature)
#     public_key = payload["cnf"]["pk"]

#     if not verify_pop_signature(message, signature, public_key):
#         raise HTTPException(status_code=403, detail="Invalid PoP signature")

#     return {"message": "Access granted"}

# ---------------- CHALLENGE ISSUE ----------------

@app.get("/challenge")
def issue_challenge():
    challenge_id = str(uuid.uuid4())
    nonce_bytes = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode()

    challenges[challenge_id] = {
        "nonce": nonce_b64,
        "issued_at": time.time(),
        "used": False,
    }

    log_event("system", "n/a", "CHALLENGE_ISSUED", "SUCCESS")

    return {
        "challenge_id": challenge_id,
        "nonce": nonce_b64,
    }

# ---------------- CHALLENGE VERIFY (FIXED) ----------------

@app.post("/challenge-verify")
def verify_challenge(
    challenge_id: str,
    signature: str,
    user_id: str,
    device_id: str,
):
    challenge = challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=401, detail="Invalid challenge")

    if challenge["used"]:
        raise HTTPException(status_code=403, detail="Challenge already used")

    if user_id not in registered_devices or device_id not in registered_devices[user_id]:
        raise HTTPException(status_code=403, detail="Unknown device")

    challenge["used"] = True

    nonce_bytes = base64.b64decode(challenge["nonce"])
    signature_bytes = base64.b64decode(signature)
    public_key = registered_devices[user_id][device_id]

    if not verify_pop_signature(nonce_bytes, signature_bytes, public_key):
        raise HTTPException(status_code=403, detail="Invalid signature")

    log_event(user_id, device_id, "CHALLENGE_VERIFY", "SUCCESS")
    return {"message": "Challenge verified successfully"}

# ---------------- TOKEN ROTATION (FIXED) ----------------

@app.post("/rotate-token")
def rotate_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    jti = payload["jti"]
    if jti in revoked_tokens:
        raise HTTPException(status_code=401, detail="Token already revoked")

    revoked_tokens.add(jti)

    new_token = generate_token(
        payload["sub"],
        payload["device_id"],
        payload["cnf"]["pk"],
    )

    log_event(payload["sub"], payload["device_id"], "ROTATE_TOKEN", "SUCCESS")
    return {"access_token": new_token}

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

