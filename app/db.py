from pymongo import MongoClient
import os

client = MongoClient(os.environ["MONGODB_URI"])
db = client[os.environ["MONGO_DB"]]
audit_logs = db[os.environ["MONGO_COLLECTION"]]
