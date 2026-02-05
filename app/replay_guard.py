import hashlib
from app.redis_client import redis_client

# ===============================
# CONFIG
# ===============================

JTI_TTL_SECONDS = 300        # 5 minutes
SIG_TTL_SECONDS = 60         # PoP signatures are very short-lived

# ===============================
# HELPERS
# ===============================

def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

# ===============================
# REPLAY CHECKS
# ===============================

# app/replay_guard.py
def check_and_mark_jti(jti: str) -> bool:
    """
    Returns True ONLY if this is a replay
    """
    key = f"jti:{jti}"

    inserted = redis_client.set(
        key,
        "1",
        nx=True,
        ex=JTI_TTL_SECONDS,
    )

    # ✅ inserted == True  → first time (NOT replay)
    # ❌ inserted == None → already exists (REPLAY)
    return inserted is None



def check_and_mark_signature(sig: str) -> bool:
    key = f"sig:{sig}"

    inserted = redis_client.set(
        key,
        "1",
        nx=True,
        ex=SIG_TTL_SECONDS,
    )

    return inserted is None

