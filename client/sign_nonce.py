import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Load client private key
with open("client_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Nonce received from /challenge (Base64 string)
nonce_b64 = "BIICQMCOb6PE/d9tBSw8Hg=="

# Decode Base64 nonce → bytes
nonce_bytes = base64.b64decode(nonce_b64)

# Sign the nonce bytes
signature = private_key.sign(
    nonce_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Encode signature to Base64 for transport
signature_b64 = base64.b64encode(signature).decode()

print("Signed Nonce (Base64):")
print(signature_b64)
