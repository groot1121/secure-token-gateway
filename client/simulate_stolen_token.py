import requests
import time

BASE = "http://127.0.0.1:8000"

print("🚨 Simulating stolen token attack")

# using a fake stolen token
token = "stolen_token_example"

for i in range(10):

    r = requests.get(
        f"{BASE}/protected",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Pop-Signature": "fake"
        }
    )

    print("Attempt", i, r.status_code)

    time.sleep(0.2)