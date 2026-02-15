from pymongo import MongoClient
import os

client = MongoClient(os.environ["MONGODB_URI"])
db = client[os.environ["MONGO_DB"]]
audit_logs = db[os.environ["MONGO_COLLECTION"]]


def insert_audit_log(doc: dict):
    audit_logs.insert_one(doc)


def get_last_audit_hash() -> str:
    doc = audit_logs.find_one(
        {"hash": {"$exists": True}},
        sort=[("created_at", -1)],
        projection={"hash": 1},
    )
    return doc["hash"] if doc else "GENESIS"


def iter_audit_logs():
    return audit_logs.find(
        {"hash": {"$exists": True}},
        sort=[("created_at", 1)],
    )
