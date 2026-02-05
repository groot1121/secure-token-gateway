import json
from datetime import datetime
from app.crypto_utils import encrypt_log
from app.db import audit_logs

def log_event(user_id, device_id, action, status, payload=None):
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "user_id": user_id,
        "device_id": device_id,
        "action": action,
        "status": status,
        "payload": payload,
    }

    encrypted = encrypt_log(json.dumps(entry).encode())

    audit_logs.insert_one({
        "enc": encrypted,
        "created_at": datetime.utcnow(),
    })
