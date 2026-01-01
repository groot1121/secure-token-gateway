# app/data_store.py
import time

# Token rotation tracking
active_tokens = set()
revoked_tokens = set()

# Challenge–Response store
# challenge_id -> { nonce, expiry }
challenges = {}
