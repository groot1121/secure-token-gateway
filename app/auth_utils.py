import base64
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta
import uuid

PRIVATE_KEY_PATH = "keys/private.pem"
PUBLIC_KEY_PATH = "keys/public.pem"


# ================= TOKEN GENERATION =================

def generate_token(user_id, device_id, public_key):

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read()

    payload = {
        "sub": user_id,
        "device_id": device_id,
        "iat": datetime.utcnow(),
        # 🔐 Short‑lived token (2 minutes)
        "exp": datetime.utcnow() + timedelta(minutes=2),
        "jti": str(uuid.uuid4()),
        "cnf": {
            "pk": public_key
        }
    }

    token = jwt.encode(payload, private_key, algorithm="RS256")

    return token


# ================= JWT VERIFICATION =================

def verify_jwt(token):
    try:
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = f.read()

        return jwt.decode(token, public_key, algorithms=["RS256"])

    except Exception:
        return None


# ================= PROOF OF POSSESSION VERIFICATION =================

def verify_pop_signature(message: bytes, signature_b64: str, public_key_str: str):

    try:
        # Normalize escaped newlines
        public_key_str = public_key_str.replace("\\n", "\n")

        public_key = serialization.load_pem_public_key(
            public_key_str.encode()
        )

        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except InvalidSignature:
        print("PoP verify failed: InvalidSignature")
        return False

    except Exception as e:
        print("PoP verify error:", str(e))
        return False