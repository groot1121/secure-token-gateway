import json
import os
import time
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.key_manager import load_aes_key

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "secure_audit.log")


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def _get_last_hash():
    if not os.path.exists(LOG_FILE):
        return "0" * 64

    with open(LOG_FILE, "r") as f:
        try:
            last_entry = json.loads(f.readlines()[-1])
            return last_entry["hash"]
        except Exception:
            return "0" * 64


def log_event(user_id: str, device_id: str, action: str, status: str):
    _ensure_log_dir()

    aesgcm = AESGCM(load_aes_key())
    prev_hash = _get_last_hash()

    log_entry = {
        "timestamp": int(time.time()),
        "user_id": user_id,
        "device_id": device_id,
        "action": action,
        "status": status,
        "prev_hash": prev_hash
    }

    plaintext = json.dumps(log_entry, sort_keys=True).encode()
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    entry_hash = hashlib.sha256(plaintext).hexdigest()

    record = {
        "hash": entry_hash,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
