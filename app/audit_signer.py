from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import base64
import os

SIGN_KEY_PATH = "keys/audit_signing_key.pem"
VERIFY_KEY_PATH = "keys/audit_signing_pub.pem"


def load_signing_key():
    with open(SIGN_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )


def load_verify_key():
    with open(VERIFY_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_root_hash(root_hash: str):
    key = load_signing_key()
    ts = datetime.utcnow().isoformat()

    message = f"{root_hash}:{ts}".encode()

    signature = key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return {
        "root_hash": root_hash,
        "timestamp": ts,
        "signature": base64.b64encode(signature).decode(),
        "alg": "RS256",
    }


def verify_root_signature(root_hash, timestamp, signature_b64):
    key = load_verify_key()

    message = f"{root_hash}:{timestamp}".encode()
    signature = base64.b64decode(signature_b64)

    try:
        key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
