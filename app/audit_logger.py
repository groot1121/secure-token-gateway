import json
from datetime import datetime
from app.crypto_utils import encrypt_log, sha256_hex, canonical_enc
from app.db import audit_logs


def log_event(user_id, device_id, action, status, payload=None):
    log_data = {
        "user_id": user_id,
        "device_id": device_id,
        "action": action,
        "status": status,
        "payload": payload,
        "ts": datetime.utcnow().isoformat(),
    }

    plaintext = json.dumps(log_data, separators=(",", ":"))
    enc = encrypt_log(plaintext)

    last = audit_logs.find_one(sort=[("created_at", -1)])
    prev_hash = last["hash"] if last else "GENESIS"

    hash_input = (prev_hash + canonical_enc(enc)).encode()
    log_hash = sha256_hex(hash_input)

    audit_logs.insert_one({
        "enc": enc,
        "prev_hash": prev_hash,
        "hash": log_hash,
        "created_at": datetime.utcnow(),
    })


def verify_audit_chain(logs):
    prev_hash = "GENESIS"
    checked = 0

    for log in logs:
        enc = log["enc"]
        expected = sha256_hex((prev_hash + canonical_enc(enc)).encode())

        if log["prev_hash"] != prev_hash:
            return {
                "valid": False,
                "checked": checked,
                "broken_at": str(log["_id"]),
                "reason": "prev_hash mismatch",
            }

        if log["hash"] != expected:
            return {
                "valid": False,
                "checked": checked,
                "broken_at": str(log["_id"]),
                "reason": "hash mismatch",
            }

        prev_hash = log["hash"]
        checked += 1

    return {
        "valid": True,
        "checked": checked,
        "broken_at": None,
    }
