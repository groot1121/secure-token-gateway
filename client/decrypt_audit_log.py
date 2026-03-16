import json
import hashlib
import base64
import os

from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGO_DB = os.getenv("MONGO_DB")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION")

AES_LOG_KEYS = os.getenv("AES_LOG_KEYS")
AES_LOG_ACTIVE = os.getenv("AES_LOG_ACTIVE")


# ================= AES KEY =================

def get_aes_key():
    keys = {}

    for item in AES_LOG_KEYS.split(","):
        version, key = item.split(":")
        keys[version] = base64.b64decode(key)

    return keys[AES_LOG_ACTIVE]


# ================= MAIN FUNCTION =================

def decrypt_logs():

    aesgcm = AESGCM(get_aes_key())

    client = MongoClient(MONGODB_URI)
    db = client[MONGO_DB]
    collection = db[MONGO_COLLECTION]

    prev_hash = "GENESIS"
    tamper_detected = False
    total_logs = 0

    # 🔹 Fetch latest 500 logs
    logs = list(
        collection.find()
        .sort("created_at", -1)
        .limit(500)
    )

    # 🔹 Reverse to restore chronological order for hash chain
    logs.reverse()

    for idx, record in enumerate(logs, start=1):

        total_logs += 1

        enc = record["enc"]

        nonce = base64.b64decode(enc["nonce"])
        ciphertext = base64.b64decode(enc["ciphertext"])

        stored_hash = record["hash"]

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            print(f"\n❌ Log #{idx} decryption failed:", e)
            tamper_detected = True
            break

        log_entry = json.loads(plaintext.decode())

        computed_hash = hashlib.sha256(
            json.dumps(log_entry, sort_keys=True).encode()
        ).hexdigest()

        hash_valid = computed_hash == stored_hash
        chain_valid = record.get("prev_hash") == prev_hash

        if not hash_valid or not chain_valid:
            tamper_detected = True

        print("\n🔎 Log #", idx)
        print(json.dumps(log_entry, indent=2))
        print("Hash Valid:", hash_valid)
        print("Chain Valid:", chain_valid)

        prev_hash = stored_hash

    print("\n==============================")
    print("Logs processed:", total_logs)
    print("Tampering detected:", tamper_detected)
    print("==============================")


# ================= RUN =================

if __name__ == "__main__":
    decrypt_logs()