# app/audit_logger.py
import os
import base64
from datetime import datetime
from pymongo import MongoClient
from cryptography.fernet import Fernet

_client = None
_collection = None
_fernet = None


def init_audit_logger():
    global _client, _collection, _fernet

    mongo_uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGO_DB")
    collection_name = os.getenv("MONGO_COLLECTION")
    aes_key = os.getenv("AES_LOG_KEY")

    if not mongo_uri:
        raise RuntimeError("MONGODB_URI not set")
    if not aes_key:
        raise RuntimeError("AES_LOG_KEY not set")

    _client = MongoClient(mongo_uri)
    _collection = _client[db_name][collection_name]
    _fernet = Fernet(aes_key.encode())


def log_event(user_id, device_id, event, status, payload=None):
    encrypted_payload = None

    if payload is not None:
        encrypted_payload = base64.b64encode(
            _fernet.encrypt(str(payload).encode())
        ).decode()

    _collection.insert_one(
        {
            "user_id": user_id,
            "device_id": device_id,
            "event": event,
            "status": status,
            "encrypted_payload": encrypted_payload,
            "created_at": datetime.utcnow(),
        }
    )
