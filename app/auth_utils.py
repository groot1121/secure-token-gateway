# app/auth_utils.py

import jwt
import time
import uuid
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.key_manager import load_private_key, load_public_key
from app.data_store import (
    active_device_tokens,
    revoked_tokens,
    cleanup_expired_tokens,
)

ALGORITHM = "RS256"

TOKEN_LIFETIME_SECONDS = 600


# ====================================================
# TOKEN GENERATION (WITH AUTOMATIC DEVICE ROTATION)
# ====================================================

def generate_token(user_id: str, device_id: str, client_public_key: str):

    cleanup_expired_tokens()

    now = int(time.time())
    exp = now + TOKEN_LIFETIME_SECONDS
    jti = str(uuid.uuid4())

    device_key = f"{user_id}:{device_id}"

    # 🔁 Revoke old token if device already has one
    if device_key in active_device_tokens:
        old_jti = active_device_tokens[device_key]["jti"]
        revoked_tokens.add(old_jti)

    payload = {
        "sub": user_id,
        "device_id": device_id,
        "iat": now,
        "exp": exp,
        "jti": jti,
        "cnf": {
            "pk": client_public_key
        }
    }

    private_key = load_private_key()
    token = jwt.encode(payload, private_key, algorithm=ALGORITHM)

    # Store active token for this device
    active_device_tokens[device_key] = {
        "jti": jti,
        "exp": exp
    }

    return token


# ====================================================
# VERIFY JWT
# ====================================================

def verify_jwt(token: str):
    try:
        cleanup_expired_tokens()

        public_key = load_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        jti = payload.get("jti")
        device_key = f"{payload['sub']}:{payload['device_id']}"

        # ❌ Reject revoked tokens
        if jti in revoked_tokens:
            return None

        # ❌ Reject if no active token for device
        if device_key not in active_device_tokens:
            return None

        # ❌ Reject if token is not the current active one
        if active_device_tokens[device_key]["jti"] != jti:
            return None

        return payload

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ====================================================
# VERIFY POP SIGNATURE
# ====================================================

def verify_pop_signature(message: bytes, signature_b64, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )

        if isinstance(signature_b64, str):
            signature = base64.b64decode(signature_b64.encode())
        else:
            signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return True

    except Exception as e:
        print("PoP verify failed:", e)
        return False