import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEY = base64.urlsafe_b64decode(os.environ["AES_LOG_KEY"])
aesgcm = AESGCM(KEY)

def encrypt_log(data: bytes) -> dict:
    nonce = os.urandom(12)  # GCM standard
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def decrypt_log(enc: dict) -> bytes:
    nonce = base64.b64decode(enc["nonce"])
    ciphertext = base64.b64decode(enc["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)
