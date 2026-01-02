import json
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG_FILE = "logs/secure_audit.log"
AES_KEY_FILE = "keys/aes_key.bin"

def load_aes_key():
    with open(AES_KEY_FILE, "rb") as f:
        return f.read()

def decrypt_logs():
    aesgcm = AESGCM(load_aes_key())
    prev_hash = "0" * 64

    with open(LOG_FILE, "r") as f:
        for idx, line in enumerate(f, start=1):
            record = json.loads(line)

            nonce = base64.b64decode(record["nonce"])
            ciphertext = base64.b64decode(record["ciphertext"])
            stored_hash = record["hash"]

            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                print(f"\n❌ Log #{idx} decryption failed:", e)
                break

            log_entry = json.loads(plaintext.decode())

            computed_hash = hashlib.sha256(
                json.dumps(log_entry, sort_keys=True).encode()
            ).hexdigest()

            print(f"\nLog #{idx}")
            print("Decrypted Entry:", log_entry)
            print("Hash valid:", computed_hash == stored_hash)
            print("Chain valid:", log_entry.get("prev_hash") == prev_hash)

            prev_hash = stored_hash

if __name__ == "__main__":
    decrypt_logs()
