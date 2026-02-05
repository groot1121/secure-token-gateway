from slowapi import Limiter
from slowapi.util import get_remote_address
import os

# Default: 60 requests per minute per IP
DEFAULT_RATE = os.getenv("RATE_LIMIT", "60/minute")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[DEFAULT_RATE],
)
