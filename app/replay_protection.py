import time
from threading import Lock

# jti -> timestamp
_used_jtis: dict[str, float] = {}
_lock = Lock()

# seconds (match JWT expiry or slightly more)
JTI_TTL_SECONDS = 300


def is_replay(jti: str) -> bool:
    now = time.time()

    with _lock:
        # cleanup expired entries
        expired = [
            k for k, ts in _used_jtis.items()
            if now - ts > JTI_TTL_SECONDS
        ]
        for k in expired:
            del _used_jtis[k]

        if jti in _used_jtis:
            return True

        _used_jtis[jti] = now
        return False
