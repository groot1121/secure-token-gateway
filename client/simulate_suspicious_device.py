import requests

BASE = "http://127.0.0.1:8000"

print("🚨 Suspicious device registration flood")

for i in range(20):

    r = requests.post(
        f"{BASE}/register-device",
        json={
            "user_id": "attacker",
            "device_id": f"device-{i}",
            "public_key": "fake_key"
        }
    )

    print("Device", i, r.status_code)