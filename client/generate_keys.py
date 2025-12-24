from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pair
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

private_key = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save keys
with open("client_private_key.pem", "wb") as f:
    f.write(private_key)

with open("client_public_key.pem", "wb") as f:
    f.write(public_key)

print("Client keys generated successfully")
