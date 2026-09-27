from slowapi import Limiter
from slowapi.util import get_remote_address

# Single shared limiter, keyed by client IP. Mounted on the app in main.py
# and applied per-route where abuse hurts most (login, register).
limiter = Limiter(key_func=get_remote_address)
