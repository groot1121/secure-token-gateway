# app/data_store.py
import time

# -----------------------------
# Token rotation storage
# -----------------------------

# device_key -> { jti, exp }
# device_key = f"{user_id}:{device_id}"
active_device_tokens = {}

# revoked JTIs
revoked_tokens = set()

# Optional replay guard (if you use it elsewhere)
used_jtis = set()
used_signatures = set()

# -----------------------------
# Cleanup expired tokens
# -----------------------------
def cleanup_expired_tokens():
    now = int(time.time())
    expired_devices = []

    for device_key, token_data in active_device_tokens.items():
        if token_data["exp"] <= now:
            expired_devices.append(device_key)

    for device_key in expired_devices:
        old_jti = active_device_tokens[device_key]["jti"]
        revoked_tokens.add(old_jti)
        del active_device_tokens[device_key]