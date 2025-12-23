from fastapi import FastAPI, Header, HTTPException
import base64
from app.auth_utils import generate_token, verify_jwt, verify_pop_signature
from app.key_manager import generate_rsa_keys, generate_aes_key

app = FastAPI(title="Cryptographically Secured Access Token System")

# In‑memory device store
# { user_id: { device_id: public_key } }
registered_devices = {}


@app.on_event("startup")
def startup_event():
    generate_rsa_keys()
    generate_aes_key()


@app.post("/register-device")
def register_device(user_id: str, device_id: str, public_key: str):
    if user_id not in registered_devices:
        registered_devices[user_id] = {}

    registered_devices[user_id][device_id] = public_key
    return {"message": "Device and public key registered successfully"}


@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    if (
        user_id not in registered_devices
        or device_id not in registered_devices[user_id]
    ):
        raise HTTPException(status_code=403, detail="Device not registered")

    client_public_key = registered_devices[user_id][device_id]
    token = generate_token(user_id, device_id, client_public_key)
    return {"access_token": token}


@app.get("/protected")
def protected_endpoint(
    authorization: str = Header(...),
    x_pop_signature: str = Header(...)
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")

    token = authorization.split(" ")[1]
    payload = verify_jwt(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    message = b"GET:/protected"
    signature = base64.b64decode(x_pop_signature)
    public_key = payload["cnf"]["pk"]

    if not verify_pop_signature(message, signature, public_key):
        raise HTTPException(status_code=403, detail="PoP verification failed")

    return {
        "message": "Access granted with Proof‑of‑Possession",
        "user": payload["sub"],
        "device": payload["device_id"]
    }
