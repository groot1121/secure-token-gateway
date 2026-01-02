# app/key_manager.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "keys"

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "rsa_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "rsa_public.pem")
AES_KEY_PATH = os.path.join(KEYS_DIR, "aes_key.bin")


# ---------------- RSA KEYS ----------------

def generate_rsa_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)

    # ✅ Do NOT overwrite existing keys
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        return

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


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ---------------- AES KEY ----------------

def generate_aes_key():
    os.makedirs(KEYS_DIR, exist_ok=True)

    # ✅ Do NOT overwrite existing AES key
    if os.path.exists(AES_KEY_PATH):
        return

    with open(AES_KEY_PATH, "wb") as f:
        f.write(os.urandom(32))  # 256‑bit AES key


def load_aes_key():
    with open(AES_KEY_PATH, "rb") as f:
        return f.read()
