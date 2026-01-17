import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY = os.getenv("AES_LOG_KEY").encode()

def encrypt_payload(data: bytes) -> str:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ciphertext).decode()
