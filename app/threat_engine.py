import asyncio
import math
import time

# ================= CONFIG =================

DECAY_LAMBDA = 0.08        # how fast risk cools down
QUARANTINE_THRESHOLD = 800
ATTACK_THRESHOLD = 1000

# ================= STATE =================

device_risk = {}
device_threat = {}

global_risk = 0
global_threat = "NORMAL"

last_update = time.time()

# ================= CORE =================

def update_risk(user_id, device_id, action, status):
    global global_risk, global_threat, last_update

    key = f"{user_id}:{device_id}"

    # Initialize
    if key not in device_risk:
        device_risk[key] = 0
        device_threat[key] = "NORMAL"

    # Risk weights
    weight_map = {
    "GEO_ANOMALY": 120,
    "REPLAY_JTI": 200,
    "REPLAY_SIGNATURE": 250,
    "BAD_SIGNATURE": 300,
    "ACCESS_DENIED": 150,
    "TOKEN_BLOCKED": 180,
    "TOKEN_REVOKED": 220,
    "REPLAY_ATTACK": 350,
    "ROTATE_DENIED": 200,
}

    weight = weight_map.get(status, 20)

    device_risk[key] += weight
    global_risk += weight

    # Determine device threat
    if device_risk[key] >= ATTACK_THRESHOLD:
        device_threat[key] = "ATTACK"
    elif device_risk[key] >= QUARANTINE_THRESHOLD:
        device_threat[key] = "HIGH"
    elif device_risk[key] >= 400:
        device_threat[key] = "ELEVATED"
    else:
        device_threat[key] = "NORMAL"

    # Determine global threat
    if global_risk >= 2000:
        global_threat = "ATTACK"
    elif global_risk >= 1200:
        global_threat = "HIGH"
    elif global_risk >= 600:
        global_threat = "ELEVATED"
    else:
        global_threat = "NORMAL"

    return {
        "device_risk": device_risk[key],
        "device_threat": device_threat[key],
        "global_risk": global_risk,
        "global_threat": global_threat,
    }

# ================= EXPONENTIAL DECAY LOOP =================
async def risk_decay_loop():
    global global_risk, global_threat, last_update

    while True:
        await asyncio.sleep(1)

        now = time.time()
        dt = now - last_update
        last_update = now

        decay_factor = math.exp(-DECAY_LAMBDA * dt)

        global_risk *= decay_factor

        for key in list(device_risk.keys()):

            device_risk[key] *= decay_factor

            # Recalculate threat level after decay
            if device_risk[key] >= ATTACK_THRESHOLD:
                device_threat[key] = "ATTACK"
            elif device_risk[key] >= QUARANTINE_THRESHOLD:
                device_threat[key] = "HIGH"
            elif device_risk[key] >= 400:
                device_threat[key] = "ELEVATED"
            else:
                device_threat[key] = "NORMAL"

        # Global threat recompute
        if global_risk >= 2000:
            global_threat = "ATTACK"
        elif global_risk >= 1200:
            global_threat = "HIGH"
        elif global_risk >= 600:
            global_threat = "ELEVATED"
        else:
            global_threat = "NORMAL"
        if global_risk < 1:
            global_risk = 0

        for key in device_risk:
            if device_risk[key] < 1:
                device_risk[key] = 0


# ================= GETTERS =================

def get_device_threat(user_id, device_id):
    key = f"{user_id}:{device_id}"
    return device_threat.get(key, "NORMAL")


def get_global_risk_score():
    return int(global_risk)


def get_global_threat_level():
    return global_threat


# ================= RESET FUNCTIONS =================

def reset_risk():
    global device_risk, device_threat, global_risk, global_threat

    device_risk = {}
    device_threat = {}
    global_risk = 0
    global_threat = "NORMAL"


def reset_device_risk(user_id, device_id):
    key = f"{user_id}:{device_id}"

    device_risk[key] = 0
    device_threat[key] = "NORMAL"