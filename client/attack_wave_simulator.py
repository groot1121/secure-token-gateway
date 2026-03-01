import requests
import threading
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

BASE_URL = "http://127.0.0.1:8000"

USER_ID = "attacker"
DEVICE_ID = "evil-device"

# ================= GENERATE KEYPAIR =================

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# ================= REGISTER DEVICE =================

requests.post(
    f"{BASE_URL}/register-device",
    json={
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "public_key": public_pem
    }
)

# ================= GET TOKEN LEGITIMATELY =================

def get_legit_token():

    r = requests.post(
        f"{BASE_URL}/challenge",
        params={"user_id": USER_ID, "device_id": DEVICE_ID}
    )

    challenge = r.json()["challenge"]
    raw_nonce = base64.b64decode(challenge)

    signature = private_key.sign(
        raw_nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode()

    requests.post(
        f"{BASE_URL}/verify-challenge",
        json={
            "user_id": USER_ID,
            "device_id": DEVICE_ID,
            "signature": signature_b64
        }
    )

    r = requests.post(
        f"{BASE_URL}/issue-token",
        params={"user_id": USER_ID, "device_id": DEVICE_ID}
    )

    return r.json()["access_token"]

print("🎯 Getting legitimate token...")
token = get_legit_token()

payload_part = token.split(".")[1]
payload_json = base64.urlsafe_b64decode(payload_part + "===").decode()
payload = json.loads(payload_json)

message = f"ACCESS:{payload['jti']}".encode()

valid_signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

valid_signature_b64 = base64.b64encode(valid_signature).decode()

# ================= ATTACK FUNCTIONS =================

def replay_attack():
    for _ in range(20):
        requests.get(
            f"{BASE_URL}/protected",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Pop-Signature": valid_signature_b64
            }
        )

def invalid_signature_attack():
    for _ in range(20):
        requests.get(
            f"{BASE_URL}/protected",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Pop-Signature": "INVALID_SIGNATURE_ATTACK"
            }
        )

def brute_token_attempt():
    for _ in range(20):
        requests.post(
            f"{BASE_URL}/issue-token",
            params={
                "user_id": USER_ID,
                "device_id": DEVICE_ID
            }
        )

# ================= LAUNCH ATTACK WAVES =================

print("💣 Launching attack wave...")

threads = []

for _ in range(5):
    t1 = threading.Thread(target=replay_attack)
    t2 = threading.Thread(target=invalid_signature_attack)
    t3 = threading.Thread(target=brute_token_attempt)

    threads.extend([t1, t2, t3])

for t in threads:
    t.start()

for t in threads:
    t.join()

print("🔥 Attack wave complete.")