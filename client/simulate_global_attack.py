import requests
import threading
import time
import random

BASE = "http://127.0.0.1:8000"

print("🌍 GLOBAL CYBER ATTACK SIMULATION STARTED")

# ----------------------------
# Replay attack
# ----------------------------

def replay_attack():

    token = "fake_replay_token"

    for i in range(50):

        requests.get(
            f"{BASE}/protected",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Pop-Signature": "fake"
            }
        )

        time.sleep(0.05)


# ----------------------------
# Stolen token attack
# ----------------------------

def stolen_token():

    token = "stolen_token"

    for i in range(50):

        requests.get(
            f"{BASE}/protected",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Pop-Signature": "fake"
            }
        )

        time.sleep(0.05)


# ----------------------------
# Suspicious devices
# ----------------------------

def suspicious_devices():

    for i in range(50):

        requests.post(
            f"{BASE}/register-device",
            json={
                "user_id": "attacker",
                "device_id": f"bot-{random.randint(1000,9999)}",
                "public_key": "fake_key"
            }
        )

        time.sleep(0.1)


# ----------------------------
# Brute force
# ----------------------------

def brute_force():

    passwords = ["1234","admin","password","root","letmein"]

    for p in passwords * 20:

        requests.post(
            f"{BASE}/login",
            json={
                "username": "admin",
                "password": p
            }
        )

        time.sleep(0.05)


# ----------------------------
# Run all attacks together
# ----------------------------

threads = []

for func in [replay_attack, stolen_token, suspicious_devices, brute_force]:

    t = threading.Thread(target=func)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("🔥 GLOBAL ATTACK FINISHED")