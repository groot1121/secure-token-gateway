import hmac
import hashlib
import os

AUDIT_SIGNING_KEY = os.getenv("AUDIT_SIGNING_KEY")

if not AUDIT_SIGNING_KEY:
    raise RuntimeError("AUDIT_SIGNING_KEY is not set")

def canonical_audit_string(
    user_id: str,
    device_id: str,
    event: str,
    status: str,
    encrypted_payload: str | None,
    created_at: str,
) -> str:
    return (
        f"{user_id}|"
        f"{device_id}|"
        f"{event}|"
        f"{status}|"
        f"{encrypted_payload if encrypted_payload is not None else 'null'}|"
        f"{created_at}"
    )

def sign_audit_log(canonical_string: str) -> str:
    return hmac.new(
        AUDIT_SIGNING_KEY.encode("utf-8"),
        canonical_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
