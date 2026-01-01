# app/key_manager.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

KEYS_DIR = "keys"

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "rsa_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "rsa_public.pem")
AES_KEY_PATH = os.path.join(KEYS_DIR, "aes_key.bin")

def generate_rsa_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def generate_aes_key():
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(AES_KEY_PATH, "wb") as f:
        f.write(os.urandom(32))

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return f.read()

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read()
