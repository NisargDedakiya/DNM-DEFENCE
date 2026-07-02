"""
Per-client scan concurrency guard (Module 7 fair scheduling). Prevents one
client with a large asset inventory from monopolizing the shared worker
pool -- caps how many scans for the same client can run at once, using a
Redis counter as the source of truth across however many workers are
running (settings.MAX_CONCURRENT_SCANS_PER_CLIENT was already declared
but never read anywhere until now).
"""
import redis

from app.core.config import settings

_redis = redis.from_url(settings.REDIS_URL, decode_responses=True)

_KEY_PREFIX = "scan_inflight:"
_SLOT_TTL_SECONDS = 3600  # safety net: auto-expires the counter if a worker crashes without releasing


def try_acquire_scan_slot(client_id: str) -> bool:
    key = f"{_KEY_PREFIX}{client_id}"
    count = _redis.incr(key)
    if count == 1:
        _redis.expire(key, _SLOT_TTL_SECONDS)
    if count > settings.MAX_CONCURRENT_SCANS_PER_CLIENT:
        _redis.decr(key)
        return False
    return True


def release_scan_slot(client_id: str) -> None:
    key = f"{_KEY_PREFIX}{client_id}"
    if _redis.decr(key) < 0:
        _redis.set(key, 0)
