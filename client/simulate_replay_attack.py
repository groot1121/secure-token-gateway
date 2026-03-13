import requests
import time

BASE = "http://127.0.0.1:8000"

print("🚨 Replay attack simulation")

token = "replay_token_example"

for i in range(10):

    r = requests.get(
        f"{BASE}/protected",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Pop-Signature": "replay"
        }
    )

    print("Attempt", i, r.status_code)

    time.sleep(0.2)