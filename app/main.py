from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uuid
import os
import base64

from app.auth_utils import generate_token, verify_jwt, verify_pop_signature
from app.key_manager import generate_rsa_keys, generate_aes_key
from app.data_store import challenges, active_tokens, revoked_tokens
from app.audit_logger import log_event

app = FastAPI(title="Zero‑Day Secure Token Gateway")
security = HTTPBearer()

registered_devices = {}

@app.on_event("startup")
def startup():
    generate_rsa_keys()
    generate_aes_key()

@app.post("/register-device")
def register_device(user_id: str, device_id: str, public_key: str):
    registered_devices.setdefault(user_id, {})
    registered_devices[user_id][device_id] = public_key
    return {"message": "Device registered"}

@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    if user_id not in registered_devices or device_id not in registered_devices[user_id]:
        raise HTTPException(status_code=403)

    pk = registered_devices[user_id][device_id]
    token = generate_token(user_id, device_id, pk)

    log_event(user_id, device_id, "ISSUE_TOKEN", "SUCCESS")
    return {"access_token": token}

@app.get("/protected")
def protected(
    creds: HTTPAuthorizationCredentials = Depends(security),
    x_pop_signature: str = Header(..., alias="X-Pop-Signature")
):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401)

    message = b"GET:/protected"
    signature = base64.b64decode(x_pop_signature)
    public_key = payload["cnf"]["pk"]

    if not verify_pop_signature(message, signature, public_key):
        raise HTTPException(status_code=403)

    return {"message": "Access granted"}

@app.get("/challenge")
def challenge(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401)

    challenge_id = str(uuid.uuid4())
    nonce = os.urandom(16)

    challenges[challenge_id] = nonce
    log_event(payload["sub"], payload["device_id"], "CHALLENGE_ISSUED", "SUCCESS")

    return {
        "challenge_id": challenge_id,
        "nonce": base64.b64encode(nonce).decode()
    }

@app.post("/challenge-verify")
def challenge_verify(
    challenge_id: str,
    signature: str,
    creds: HTTPAuthorizationCredentials = Depends(security)
):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401)

    if challenge_id not in challenges:
        raise HTTPException(status_code=403)

    nonce = challenges.pop(challenge_id)
    sig = base64.b64decode(signature)

    if not verify_pop_signature(nonce, sig, payload["cnf"]["pk"]):
        log_event(payload["sub"], payload["device_id"], "CHALLENGE_VERIFY", "FAILED")
        raise HTTPException(status_code=403)

    log_event(payload["sub"], payload["device_id"], "CHALLENGE_VERIFY", "SUCCESS")
    return {"message": "Challenge verified"}

@app.post("/rotate-token")
def rotate_token(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_jwt(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401)

    old_jti = payload["jti"]
    revoked_tokens.add(old_jti)
    active_tokens.discard(old_jti)

    new_token = generate_token(
        payload["sub"],
        payload["device_id"],
        payload["cnf"]["pk"]
    )

    log_event(payload["sub"], payload["device_id"], "ROTATE_TOKEN", "SUCCESS")
    return {"access_token": new_token}
