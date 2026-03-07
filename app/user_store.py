from pymongo import MongoClient
from passlib.hash import bcrypt
import os

MONGODB_URI = os.getenv("MONGODB_URI")
MONGO_DB = os.getenv("MONGO_DB")

client = MongoClient(MONGODB_URI)
db = client[MONGO_DB]

users = db["users"]

# create user
def create_user(username, password):
    if users.find_one({"username": username}):
        return False

    users.insert_one({
        "username": username,
        "password": bcrypt.hash(password)
    })
    return True


# verify user
def verify_user(username, password):

    user = users.find_one({"username": username})

    if not user:
        return False

    return bcrypt.verify(password, user["password"])