import jwt
import time
import uuid
from .key_manager import load_private_key

ALGORITHM = "RS256"


def generate_token(user_id: str, device_id: str, cnf: dict = None):
    now = int(time.time())

    payload = {
        "sub": user_id,
        "device_id": device_id,
        "iat": now,
        "exp": now + 300,  # 5 minutes
        "jti": str(uuid.uuid4())
    }

    if cnf:
        payload["cnf"] = cnf  # Proof‑of‑Possession info

    private_key = load_private_key()
    token = jwt.encode(payload, private_key, algorithm=ALGORITHM)

    return token
