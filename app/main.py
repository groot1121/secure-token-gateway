# app/main.py
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import base64, uuid, os, time

from app.auth_utils import generate_token, verify_jwt, verify_pop_signature
from app.key_manager import generate_rsa_keys, generate_aes_key
from app.data_store import challenges, revoked_tokens, active_tokens

app = FastAPI(title="Zero‑Trust Secure Token Gateway")
security = HTTPBearer()

registered_devices = {}

@app.on_event("startup")
def startup_event():
    generate_rsa_keys()
    generate_aes_key()


# -------------------- MODULE 1 --------------------
@app.post("/register-device")
def register_device(user_id: str, device_id: str, public_key: str):
    registered_devices.setdefault(user_id, {})
    registered_devices[user_id][device_id] = public_key
    return {"message": "Device registered successfully"}


@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    if user_id not in registered_devices or device_id not in registered_devices[user_id]:
        raise HTTPException(status_code=403, detail="Device not registered")

    public_key = registered_devices[user_id][device_id]
    token = generate_token(user_id, device_id, public_key)
    return {"access_token": token}


# -------------------- MODULE 2 --------------------
@app.get("/protected")
def protected(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    x_pop_signature: str = Header(...)
):
    payload = verify_jwt(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    message = b"GET:/protected"
    signature = base64.b64decode(x_pop_signature)
    pub_key = payload["cnf"]["pk"]

    if not verify_pop_signature(message, signature, pub_key):
        raise HTTPException(status_code=403, detail="PoP verification failed")

    return {"message": "Access granted"}


# -------------------- MODULE 3 --------------------
@app.post("/rotate-token")
def rotate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    old_jti = payload["jti"]
    revoked_tokens.add(old_jti)
    active_tokens.discard(old_jti)

    new_token = generate_token(
        payload["sub"],
        payload["device_id"],
        payload["cnf"]["pk"]
    )

    return {"access_token": new_token, "message": "Token rotated successfully"}


# -------------------- MODULE 4 (NEW) --------------------
@app.get("/challenge")
def generate_challenge():
    challenge_id = str(uuid.uuid4())
    nonce = os.urandom(32)

    challenges[challenge_id] = {
        "nonce": nonce,
        "expiry": time.time() + 60
    }

    return {
        "challenge_id": challenge_id,
        "nonce": base64.b64encode(nonce).decode()
    }


@app.post("/challenge-verify")
def verify_challenge(
    challenge_id: str,
    signature: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    payload = verify_jwt(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401)

    challenge = challenges.get(challenge_id)
    if not challenge or time.time() > challenge["expiry"]:
        raise HTTPException(status_code=403, detail="Challenge expired")

    nonce = challenge["nonce"]
    pub_key = payload["cnf"]["pk"]

    if not verify_pop_signature(nonce, base64.b64decode(signature), pub_key):
        raise HTTPException(status_code=403, detail="Invalid response")

    del challenges[challenge_id]
    return {"message": "Challenge verified successfully"}
