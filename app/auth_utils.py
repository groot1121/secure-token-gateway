# app/auth_utils.py
import jwt
import time
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from app.key_manager import load_private_key, load_public_key
from app.data_store import active_tokens, revoked_tokens

ALGORITHM = "RS256"

def generate_token(user_id: str, device_id: str, client_public_key: str):
    now = int(time.time())
    jti = str(uuid.uuid4())

    payload = {
        "sub": user_id,
        "device_id": device_id,
        "iat": now,
        "exp": now + 300,
        "jti": jti,
        "cnf": {
            "pk": client_public_key
        }
    }

    private_key = load_private_key()
    token = jwt.encode(payload, private_key, algorithm=ALGORITHM)

    # ✅ ADD THIS
    active_tokens.add(jti)

    return token


def verify_jwt(token: str):
    try:
        public_key = load_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        jti = payload.get("jti")
        if jti in revoked_tokens or jti not in active_tokens:
            return None

        return payload

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def verify_pop_signature(message: bytes, signature: bytes, public_key_pem: str):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

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
