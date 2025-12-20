from fastapi import FastAPI
from app.key_manager import generate_rsa_keys, generate_aes_key
from app.auth_utils import generate_token

app = FastAPI(title="Secure Token Gateway - Module 1")


@app.on_event("startup")
def startup_event():
    generate_rsa_keys()
    generate_aes_key()


@app.get("/")
def root():
    return {"status": "Module‑1 running"}

registered_devices = {}

@app.post("/register-device")
def register_device(user_id: str, device_id: str):
    if user_id not in registered_devices:
        registered_devices[user_id] = []

    if device_id not in registered_devices[user_id]:
        registered_devices[user_id].append(device_id)

    return {
        "message": "Device registered successfully",
        "user_id": user_id,
        "device_id": device_id
    }


@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    if user_id not in registered_devices or device_id not in registered_devices[user_id]:
        return {"error": "Device not registered"}

    token = generate_token(user_id, device_id)
    return {"access_token": token}


from fastapi import Header, HTTPException
from app.auth_utils import verify_token

@app.get("/protected")
def protected_endpoint(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")

    token = authorization.split(" ")[1]
    payload = verify_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {
        "message": "Access granted",
        "user_id": payload["sub"],
        "device_id": payload["device_id"]
    }
