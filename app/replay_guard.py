import redis
import hashlib

# ================= REDIS CLIENT =================

redis_client = redis.Redis(
    host="localhost",
    port=6379,
    db=0,
    decode_responses=True
)

# ================= CONFIG =================

JTI_TTL_SECONDS = 600        # 10 minutes
SIGNATURE_TTL_SECONDS = 600 # 10 minutes

# ================= JTI REPLAY CHECK =================

def check_and_mark_jti(jti: str) -> bool:
    """
    Returns True if replay detected.
    Returns False if first time usage.
    """

    key = f"replay:jti:{jti}"

    if redis_client.exists(key):
        return True

    redis_client.setex(key, JTI_TTL_SECONDS, "used")
    return False

# ================= SIGNATURE REPLAY CHECK =================

def check_and_mark_signature(signature: str) -> bool:
    """
    Returns True if replay detected.
    Returns False if first time usage.
    """

    # Hash signature so we don't store massive base64 strings
    sig_hash = hashlib.sha256(signature.encode()).hexdigest()

    key = f"replay:sig:{sig_hash}"

    if redis_client.exists(key):
        return True

    redis_client.setex(key, SIGNATURE_TTL_SECONDS, "used")
    return False