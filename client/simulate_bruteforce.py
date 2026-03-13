import requests

BASE = "http://127.0.0.1:8000"

print("🚨 Brute force login simulation")

passwords = [
    "1234",
    "admin",
    "password",
    "root",
    "letmein"
]

for pwd in passwords:

    r = requests.post(
        f"{BASE}/login",
        json={
            "username": "admin",
            "password": pwd
        }
    )

    print("Try", pwd, r.status_code)