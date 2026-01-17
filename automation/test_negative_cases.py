import requests
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path
import time

BASE_URL = "http://127.0.0.1:8000"
USER_ID = "g1"
DEVICE_ID = "123"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_KEY_PATH = PROJECT_ROOT / "keys" / "rsa_private.pem"
PUBLIC_KEY_PATH = PROJECT_ROOT / "keys" / "rsa_public.pem"

# ---------------- Load keys ----------------

with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(), password=None
    )

with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key_pem = f.read().decode()

# ---------------- Helpers ----------------

def sign(message: bytes) -> str:
    sig = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()

def print_result(name, resp):
    print(f"{name}: {resp.status_code} {resp.text}")

# ---------------- Setup ----------------

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

auth_headers = {
    "Authorization": f"Bearer {token}",
}

# ---------------- NEGATIVE TESTS ----------------

print("\n--- NEGATIVE TESTS ---\n")

# 1. Missing PoP signature
r = requests.get(f"{BASE_URL}/protected", headers=auth_headers)
print_result("Missing PoP header", r)

# 2. Invalid PoP signature
bad_sig_headers = {
    **auth_headers,
    "X-Pop-Signature": base64.b64encode(b"invalid").decode(),
}
r = requests.get(f"{BASE_URL}/protected", headers=bad_sig_headers)
print_result("Invalid PoP signature", r)

# 3. Wrong signed message
wrong_message_sig = sign(b"GET:/wrong-endpoint")
headers = {
    **auth_headers,
    "X-Pop-Signature": wrong_message_sig,
}
r = requests.get(f"{BASE_URL}/protected", headers=headers)
print_result("Wrong signed payload", r)

# 4. Replay attack (same PoP twice)
correct_sig = sign(b"GET:/protected")
headers = {
    **auth_headers,
    "X-Pop-Signature": correct_sig,
}

r1 = requests.get(f"{BASE_URL}/protected", headers=headers)
print_result("Legitimate request", r1)

r2 = requests.get(f"{BASE_URL}/protected", headers=headers)
print_result("Replay PoP signature", r2)

# 5. Token rotation invalidates old token
rotate = requests.post(f"{BASE_URL}/rotate-token", headers=auth_headers)
new_token = rotate.json()["access_token"]

r = requests.get(
    f"{BASE_URL}/protected",
    headers={
        "Authorization": f"Bearer {token}",
        "X-Pop-Signature": correct_sig,
    },
)
print_result("Old token after rotation", r)

print("\nNegative testing complete")
