import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _load_keyring():
    raw = os.environ.get("AES_LOG_KEYS")
    if not raw:
        raise RuntimeError("AES_LOG_KEYS not set")

    keys = {}

    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue  # skip empty entries safely

        if ":" not in entry:
            raise RuntimeError(f"Invalid AES_LOG_KEYS entry (missing ':'): {entry}")

        version, b64 = entry.split(":", 1)

        try:
            key = base64.b64decode(b64, validate=True)
        except Exception as e:
            raise RuntimeError(
                f"Invalid base64 for AES_LOG_KEYS entry {version}"
            ) from e

        if len(key) != 32:
            raise RuntimeError(
                f"AES key {version} must be 32 bytes, got {len(key)}"
            )

        keys[version] = key

    if not keys:
        raise RuntimeError("No valid AES keys loaded")

    return keys

KEYRING = _load_keyring()
ACTIVE_VERSION = os.environ.get("AES_LOG_ACTIVE")

if ACTIVE_VERSION not in KEYRING:
    raise RuntimeError("AES_LOG_ACTIVE must exist in AES_LOG_KEYS")

def encrypt_log(plaintext: str) -> dict:
    key = KEYRING[ACTIVE_VERSION]
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode(),
        None
    )

    return {
        "v": ACTIVE_VERSION,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def decrypt_log(enc: dict) -> str:
    version = enc["v"]
    key = KEYRING.get(version)
    if not key:
        raise RuntimeError(f"Unknown key version {version}")

    aesgcm = AESGCM(key)
    nonce = base64.b64decode(enc["nonce"])
    ciphertext = base64.b64decode(enc["ciphertext"])

    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def canonical_enc(enc: dict) -> str:
    return json.dumps(enc, sort_keys=True, separators=(",", ":"))

def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()
