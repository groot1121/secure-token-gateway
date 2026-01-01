import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 1. Load client private key
with open("client_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# 2. Nonce received from /challenge (Base64)
nonce_b64 = "YuCDYpHQCQNENW6cIXjxrw=="

# 3. Decode nonce
nonce = base64.b64decode(nonce_b64)

# 4. Sign the nonce
signature = private_key.sign(
    nonce,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# 5. Convert signature to Base64 (to send to server)
signature_b64 = base64.b64encode(signature).decode()

print("Signed Nonce (Base64):")
print(signature_b64)
