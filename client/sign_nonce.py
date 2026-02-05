import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

nonce = "EQHJMnAFajhP8JvZ2Np6hsbVi1LQcsqwoMNkojquaIQ="  # replace with actual nonce

canonical = json.dumps(
    {"nonce": nonce},
    separators=(",", ":"),
    sort_keys=True
).encode("utf-8")

with open("client_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

signature = private_key.sign(
    canonical,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(signature.hex())
