import requests
import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

BASE_URL = "http://127.0.0.1:8000"

USER_ID = "testuser"
DEVICE_ID = "device1"

# ================= GENERATE RSA KEYS =================

print("🔐 Generating RSA key pair...")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# ================= SIGN FUNCTION =================

def sign(message: bytes):

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),  # IMPORTANT FIX
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()

# ================= REGISTER DEVICE =================

print("\n1️⃣ Registering device...")

r = requests.post(
    f"{BASE_URL}/register-device",
    json={
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "public_key": public_pem
    }
)

print(r.status_code, r.text)

# ================= CHALLENGE =================

print("\n2️⃣ Requesting challenge...")

r = requests.post(
    f"{BASE_URL}/challenge",
    params={
        "user_id": USER_ID,
        "device_id": DEVICE_ID
    }
)

challenge = r.json()["challenge"]
raw_nonce = base64.b64decode(challenge)

# ================= VERIFY =================

print("\n3️⃣ Verifying challenge...")

signature = sign(raw_nonce)

r = requests.post(
    f"{BASE_URL}/verify-challenge",
    json={
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "signature": signature
    }
)

print(r.status_code, r.text)

if r.status_code != 200:
    print("❌ Challenge verification failed")
    exit()

# ================= ISSUE TOKEN =================

print("\n4️⃣ Issuing token...")

r = requests.post(
    f"{BASE_URL}/issue-token",
    params={
        "user_id": USER_ID,
        "device_id": DEVICE_ID
    }
)

print("Server response:", r.status_code, r.text)

try:
    data = r.json()
except:
    print("❌ Server returned non‑JSON response")
    exit()

if "access_token" not in data:
    print("❌ Token issue failed:", data)
    exit()
token = data["access_token"]
print("✅ Token issued")

payload_part = token.split(".")[1]
payload_json = base64.urlsafe_b64decode(payload_part + "===").decode()
payload = json.loads(payload_json)

jti = payload["jti"]

# ================= ACCESS TEST =================

print("\n5️⃣ Accessing protected endpoint")

message = f"ACCESS:{jti}".encode()
signature = sign(message)

r = requests.get(
    f"{BASE_URL}/protected",
    headers={
        "Authorization": f"Bearer {token}",
        "X-Pop-Signature": signature
    }
)

print(r.status_code, r.text)

# ================= TOKEN ROTATION =================

print("\n6️⃣ Rotating token")

rotate_msg = f"ROTATE:{jti}".encode()
rotate_sig = sign(rotate_msg)

r = requests.post(
    f"{BASE_URL}/rotate-token",
    headers={
        "Authorization": f"Bearer {token}",
        "X-Pop-Signature": rotate_sig
    }
)

print(r.status_code, r.text)

if r.status_code == 200:

    token = r.json()["access_token"]

    payload_part = token.split(".")[1]
    payload_json = base64.urlsafe_b64decode(payload_part + "===").decode()
    payload = json.loads(payload_json)

    jti = payload["jti"]

    print("✅ New token received")

# ================= NORMAL ACCESS LOOP =================

print("\n7️⃣ Normal access")

for i in range(3):

    message = f"ACCESS:{jti}".encode()
    signature = sign(message)

    r = requests.get(
        f"{BASE_URL}/protected",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Pop-Signature": signature
        }
    )

    print(f"Access {i+1}:", r.status_code)

    time.sleep(1)

# ================= REPLAY ATTACK TEST =================

print("\n8️⃣ Triggering replay flood attack")

message = f"ACCESS:{jti}".encode()
signature = sign(message)

for i in range(15):

    r = requests.get(
        f"{BASE_URL}/protected",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Pop-Signature": signature
        }
    )

    print(f"Replay {i+1}:", r.status_code)

    time.sleep(0.2)