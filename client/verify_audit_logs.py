import os
import json
import base64
from datetime import datetime
from pymongo import MongoClient

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature

# ===============================
# CONFIG
# ===============================

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("AUDIT_DB_NAME", "audit_db")
COLLECTION_NAME = os.getenv("AUDIT_COLLECTION", "audit_logs")

SIGNING_KEY_PATH = os.getenv(
    "AUDIT_SIGNING_KEY_PATH", "keys/audit_signing_key.pem"
)

PAYLOAD_KEY = os.getenv("AUDIT_PAYLOAD_KEY")  # optional

# ===============================
# LOAD KEYS
# ===============================

with open(SIGNING_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(), password=None
    )
    public_key = private_key.public_key()

cipher = Fernet(PAYLOAD_KEY.encode()) if PAYLOAD_KEY else None

# ===============================
# HELPERS
# ===============================

def canonicalize(record: dict) -> bytes:
    """
    Must EXACTLY match audit_logger canonicalization.
    """
    return json.dumps(
        record,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def verify_signature(record: dict, signature_b64: str) -> bool:
    data = canonicalize(record)
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def decrypt_payload(payload_b64: str | None):
    if not payload_b64 or not cipher:
        return None
    raw = base64.b64decode(payload_b64)
    return json.loads(cipher.decrypt(raw))


# ===============================
# MAIN VERIFIER
# ===============================

def main():
    client = MongoClient(MONGO_URI)
    col = client[DB_NAME][COLLECTION_NAME]

    print("🔍 Verifying audit logs...\n")

    for doc in col.find():
        signature = doc.pop("signature", None)
        _id = str(doc.get("_id"))
        doc.pop("_id", None)

        valid = verify_signature(doc, signature)

        print(f"Log {_id}")
        print(f"  ✔ Signature valid: {valid}")

        if not valid:
            print("  ❌ TAMPERING DETECTED")
            print("  ⛔ Record should not be trusted")
            print("-" * 50)
            continue

        decrypted = decrypt_payload(doc.get("encrypted_payload"))
        if decrypted:
            print(f"  🔓 Payload: {decrypted}")

        print("  ✅ Record integrity confirmed")
        print("-" * 50)


if __name__ == "__main__":
    main()
