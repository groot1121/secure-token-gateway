# app/auth_utils.py

import jwt
import time
import uuid
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.key_manager import load_private_key, load_public_key
from app.redis_client import redis_client

ALGORITHM = "RS256"
TOKEN_LIFETIME_SECONDS = 600  # 10 minutes


# ====================================================
# TOKEN GENERATION (WITH REDIS ROTATION)
# ====================================================

def generate_token(user_id: str, device_id: str, client_public_key: str):

    now = int(time.time())
    exp = now + TOKEN_LIFETIME_SECONDS
    jti = str(uuid.uuid4())

    device_key = f"active:{user_id}:{device_id}"
    revoked_key_prefix = "revoked:"

    # 🔁 Revoke old token if exists
    old_jti = redis_client.get(device_key)
    if old_jti:
        redis_client.setex(
            f"{revoked_key_prefix}{old_jti}",
            TOKEN_LIFETIME_SECONDS,
            "1"
        )

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

    # ✅ Store new active token with TTL
    redis_client.setex(
        device_key,
        TOKEN_LIFETIME_SECONDS,
        jti
    )

    return token


# ====================================================
# VERIFY JWT
# ====================================================

def verify_jwt(token: str):
    try:
        public_key = load_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        jti = payload.get("jti")
        device_key = f"active:{payload['sub']}:{payload['device_id']}"

        # ❌ Reject revoked token
        if redis_client.exists(f"revoked:{jti}"):
            return None

        # ❌ Reject if not current active device token
        active_jti = redis_client.get(device_key)
        if not active_jti or active_jti != jti:
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