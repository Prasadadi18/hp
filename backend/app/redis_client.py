"""
redis_client.py — Shared Redis client for cross-pod atomic metric counters.

All pods connect to the same Redis instance via REDIS_URL.
Metrics are written with INCR / INCRBYFLOAT so every pod's events are
counted in a single shared view — no more 1/N fragmentation.

Fallback: if Redis is unavailable every function returns None / False
and the caller degrades gracefully to the existing PostgreSQL path.
"""

import os
import json
import logging
import threading

logger = logging.getLogger("hpe.redis_client")

# ── Redis key namespace ───────────────────────────────────────────────────────
_NS = "metrics"  # redis key prefix: metrics:<field>

METRIC_KEYS = [
    "total_requests",
    "total_threats",
    "total_allowed",
    "total_monitored",
    "total_blocked",
    "total_critical",
    "total_latency_ms",
]
ATTACK_TYPES_KEY = f"{_NS}:attack_types"  # stored as a Redis Hash


def _rkey(field: str) -> str:
    return f"{_NS}:{field}"


# ── Lazy singleton ────────────────────────────────────────────────────────────
try:
    import redis as _redis_lib
except ImportError:
    _redis_lib = None  # type: ignore

_client = None
_initialized = False
_lock = threading.Lock()


def get_client():
    """Return a shared Redis client, or None when Redis is unavailable."""
    global _client, _initialized
    if _initialized:
        return _client
    with _lock:
        if _initialized:
            return _client
        if _redis_lib is None:
            logger.warning("[Redis] redis-py not installed — metrics counters disabled")
            _initialized = True
            return None
        try:
            url = os.getenv("REDIS_URL", "redis://redis:6379")
            c = _redis_lib.from_url(url, decode_responses=True, socket_connect_timeout=2)
            c.ping()
            _client = c
            logger.info(f"[Redis] Metrics client connected at {url}")
        except Exception as exc:
            logger.warning(f"[Redis] Unavailable ({exc}) — metrics counters degraded to DB-only")
            _client = None
        _initialized = True
    return _client


# ── Atomic counter helpers ────────────────────────────────────────────────────

def incr(field: str, amount: int = 1) -> bool:
    """Atomically increment an integer metric counter across all pods."""
    r = get_client()
    if r is None:
        return False
    try:
        r.incrby(_rkey(field), amount)
        return True
    except Exception as exc:
        logger.debug(f"[Redis] INCRBY {field} failed: {exc}")
        return False


def incr_float(field: str, amount: float) -> bool:
    """Atomically increment a float metric (e.g. total_latency_ms)."""
    r = get_client()
    if r is None:
        return False
    try:
        r.incrbyfloat(_rkey(field), amount)
        return True
    except Exception as exc:
        logger.debug(f"[Redis] INCRBYFLOAT {field} failed: {exc}")
        return False


def incr_attack_type(attack_type: str, amount: int = 1) -> bool:
    """Atomically increment an attack-type counter stored in a Redis Hash."""
    r = get_client()
    if r is None:
        return False
    try:
        r.hincrby(ATTACK_TYPES_KEY, attack_type, amount)
        return True
    except Exception as exc:
        logger.debug(f"[Redis] HINCRBY attack_types:{attack_type} failed: {exc}")
        return False


def get_counters() -> dict:
    """
    Read all shared metric counters in a single pipeline round-trip.
    Returns a dict with the same keys as _local_deltas, or an empty dict
    when Redis is unavailable.
    """
    r = get_client()
    if r is None:
        return {}
    try:
        pipe = r.pipeline(transaction=False)
        for field in METRIC_KEYS:
            pipe.get(_rkey(field))
        pipe.hgetall(ATTACK_TYPES_KEY)
        results = pipe.execute()

        counters = {}
        for i, field in enumerate(METRIC_KEYS):
            raw = results[i]
            if field == "total_latency_ms":
                counters[field] = float(raw) if raw else 0.0
            else:
                counters[field] = int(raw) if raw else 0

        attack_hash = results[len(METRIC_KEYS)] or {}
        counters["attack_types"] = {k: int(v) for k, v in attack_hash.items()}
        return counters
    except Exception as exc:
        logger.debug(f"[Redis] get_counters failed: {exc}")
        return {}


def is_available() -> bool:
    """Return True when Redis is reachable."""
    return get_client() is not None
