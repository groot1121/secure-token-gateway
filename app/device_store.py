from datetime import datetime
from app.db import devices

def register_device(user_id: str, device_id: str, public_key: str):
    devices.update_one(
        {"user_id": user_id, "device_id": device_id},
        {
            "$set": {
                "public_key": public_key,
                "updated_at": datetime.utcnow(),
            },
            "$setOnInsert": {
                "created_at": datetime.utcnow(),
            },
        },
        upsert=True,
    )

def get_device(user_id: str, device_id: str):
    return devices.find_one(
        {"user_id": user_id, "device_id": device_id},
        {"_id": 0},
    )
