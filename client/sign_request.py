import base64
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

TOKEN = "PASTE_YOUR_JWT_HERE"

# Decode JWT WITHOUT verifying (just to get jti)
payload = jwt.decode(TOKEN, options={"verify_signature": False})
jti = payload["jti"]

# Build EXACT message backend expects
MESSAGE = f"ACCESS:{jti}".encode()

with open("client_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

signature = private_key.sign(
    MESSAGE,
    padding.PKCS1v15(),   # ✅ MUST MATCH BACKEND
    hashes.SHA256()
)

print(base64.b64encode(signature).decode())