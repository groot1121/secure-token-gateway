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


@app.post("/issue-token")
def issue_token(user_id: str, device_id: str):
    token = generate_token(user_id, device_id)
    return {"access_token": token}
