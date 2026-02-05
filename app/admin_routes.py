from fastapi import APIRouter
from app.db import audit_logs
from app.crypto_utils import decrypt_log
import json

router = APIRouter(prefix="/admin")

@router.get("/audit-logs")
def get_audit_logs(limit: int = 50):
    docs = audit_logs.find().sort("created_at", -1).limit(limit)

    logs = []
    for d in docs:
        decrypted = decrypt_log(d["enc"])
        logs.append(json.loads(decrypted))

    return {
        "count": len(logs),
        "logs": logs,
    }
