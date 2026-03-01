import base64
import jwt
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# 🔹 1. Paste the FULL token you received from /issue-token
TOKEN = "PASTE_YOUR_FULL_JWT_HERE"

# 🔹 2. Decode JWT (without verifying signature)
payload = jwt.decode(TOKEN, options={"verify_signature": False})

jti = payload["jti"]
print("JTI:", jti)

# 🔹 3. Build correct message
MESSAGE = f"ACCESS:{jti}".encode()

# 🔹 4. Load private key
with open("client_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# 🔹 5. Sign message
signature = private_key.sign(
    MESSAGE,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

signature_b64 = base64.b64encode(signature).decode()
print("Signature:", signature_b64)

# 🔹 6. Call protected endpoint
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "X-Pop-Signature": signature_b64
}

response = requests.get(
    "http://127.0.0.1:8000/protected",
    headers=headers
)

print("Status:", response.status_code)
print("Response:", response.text)