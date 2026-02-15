from fastapi import APIRouter, Query
from app.db import audit_logs
from app.crypto_utils import decrypt_log, sha256_hex, canonical_enc
from cryptography.exceptions import InvalidTag
import json

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/audit-logs")
def get_audit_logs(limit: int = Query(20, le=100)):
    logs = []
    skipped = 0

    cursor = audit_logs.find().sort("created_at", -1).limit(limit)

    for d in cursor:
        enc = d.get("enc")
        if not enc:
            skipped += 1
            continue

        try:
            plaintext = decrypt_log(enc)
            data = json.loads(plaintext)

            logs.append({
                **data,
                "hash": d.get("hash"),
                "prev_hash": d.get("prev_hash"),
            })

        except (InvalidTag, ValueError, KeyError):
            skipped += 1

    return {
        "returned": len(logs),
        "skipped": skipped,
        "logs": logs,
    }


@router.get("/audit-logs/verify")
def verify_audit_chain():
    prev_hash = "GENESIS"
    index = 0

    cursor = audit_logs.find().sort("created_at", 1)

    for d in cursor:
        enc = d.get("enc")
        stored_prev = d.get("prev_hash")
        stored_hash = d.get("hash")

        if not enc or not stored_prev or not stored_hash:
            return {
                "ok": False,
                "error": "Missing fields",
                "index": index,
            }

        if stored_prev != prev_hash:
            return {
                "ok": False,
                "error": "Broken prev_hash",
                "index": index,
                "expected_prev": prev_hash,
                "found_prev": stored_prev,
            }

        expected_hash = sha256_hex(
            (prev_hash + canonical_enc(enc)).encode()
        )

        if stored_hash != expected_hash:
            return {
                "ok": False,
                "error": "Hash mismatch",
                "index": index,
                "expected_hash": expected_hash,
                "found_hash": stored_hash,
            }

        prev_hash = stored_hash
        index += 1

    return {
        "ok": True,
        "records_verified": index,
        "root_hash": prev_hash,
    }
