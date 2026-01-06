# automation/test_flow.py
import requests
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_URL = "http://127.0.0.1:8000"

# ---------------- PATHS ----------------
ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT_DIR / "keys"

PRIVATE_KEY_PATH = KEYS_DIR / "rsa_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "rsa_public.pem"

USER_ID = "g1"
DEVICE_ID = "123"

# ---------------- LOAD KEYS ----------------
with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key_pem = f.read().decode()

# ---------------- HELPERS ----------------
def sign_message(message: bytes) -> str:
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# ---------------- FLOW ----------------

print("\n[1] Register device")
requests.post(
    f"{BASE_URL}/register-device",
    params={
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "public_key": public_key_pem
    }
)

print("[2] Issue token")
resp = requests.post(
    f"{BASE_URL}/issue-token",
    params={"user_id": USER_ID, "device_id": DEVICE_ID}
)
TOKEN = resp.json()["access_token"]

print("[3] Access protected endpoint with PoP")
message = b"GET:/protected"
signature = sign_message(message)

resp = requests.get(
    f"{BASE_URL}/protected",
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "X-Pop-Signature": signature
    }
)

print("Protected status:", resp.status_code)
print(resp.text)

print("\n[4] Challenge-response")
challenge = requests.get(f"{BASE_URL}/challenge").json()

nonce_bytes = base64.b64decode(challenge["nonce"])
nonce_sig = sign_message(nonce_bytes)

resp = requests.post(
    f"{BASE_URL}/challenge-verify",
    params={
        "challenge_id": challenge["challenge_id"],
        "signature": nonce_sig,
        "user_id": USER_ID,
        "device_id": DEVICE_ID
    }
)

print("Challenge verify:", resp.status_code)
print(resp.text)

print("\n[5] Rotate token")
resp = requests.post(
    f"{BASE_URL}/rotate-token",
    headers={"Authorization": f"Bearer {TOKEN}"}
)

print("Rotate token:", resp.status_code)
print(resp.text)
