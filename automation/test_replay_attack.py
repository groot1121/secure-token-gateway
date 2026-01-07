import requests
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
USER_ID = "g1"
DEVICE_ID = "123"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_KEY_PATH = PROJECT_ROOT / "keys" / "rsa_private.pem"
PUBLIC_KEY_PATH = PROJECT_ROOT / "keys" / "rsa_public.pem"

# Load keys
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key_pem = f.read().decode()

def sign(data: bytes) -> str:
    sig = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()

print("[0] Register device")
requests.post(
    f"{BASE_URL}/register-device",
    params={
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "public_key": public_key_pem,
    },
)

print("[1] Issue token")
token_resp = requests.post(
    f"{BASE_URL}/issue-token",
    params={"user_id": USER_ID, "device_id": DEVICE_ID},
)
token = token_resp.json()["access_token"]

auth_headers = {"Authorization": f"Bearer {token}"}

print("[2] Get challenge")
challenge_resp = requests.get(f"{BASE_URL}/challenge", headers=auth_headers)
challenge = challenge_resp.json()

challenge_id = challenge["challenge_id"]
nonce = challenge["nonce"]

payload = f"{nonce}:{DEVICE_ID}".encode()
signature = sign(payload)

print("[3] First challenge verification (legitimate)")
verify_1 = requests.post(
    f"{BASE_URL}/challenge-verify",
    params={
        "challenge_id": challenge_id,
        "signature": signature,
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
    },
)
print("Status:", verify_1.status_code, verify_1.text)

print("[4] Replay attack (same nonce + same signature)")
verify_2 = requests.post(
    f"{BASE_URL}/challenge-verify",
    params={
        "challenge_id": challenge_id,
        "signature": signature,
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
    },
)
print("Status:", verify_2.status_code, verify_2.text)
