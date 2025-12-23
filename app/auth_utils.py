import jwt
import time
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from .key_manager import load_private_key, load_public_key

ALGORITHM = "RS256"


def generate_token(user_id: str, device_id: str, client_public_key: str):
    now = int(time.time())

    payload = {
        "sub": user_id,
        "device_id": device_id,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
        "cnf": {
            "pk": client_public_key
        }
    }

    private_key = load_private_key()
    return jwt.encode(payload, private_key, algorithm=ALGORITHM)


def verify_jwt(token: str):
    try:
        public_key = load_public_key()
        return jwt.decode(token, public_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


def verify_pop_signature(message: bytes, signature: bytes, public_key_pem: str):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
