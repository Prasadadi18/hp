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

# ── Admin alert counter namespace ─────────────────────────────────────────────
# Mirrors hpe_admin_stats so get_stats() can read from Redis (microseconds)
# instead of firing 3 COUNT(*) queries per WebSocket ping.
_ADMIN_NS = "hpe:stats"

ADMIN_STAT_KEYS = [
    "total_alerts",
    "pending_count",
    "critical_pending",
    "total_approved",
    "total_rejected",
    "total_auto_allowed",
    "total_alerts_created",
]


def _admin_key(field: str) -> str:
    return f"{_ADMIN_NS}:{field}"


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


# ── Admin alert counter helpers ───────────────────────────────────────────────

def admin_incr(field: str, amount: int = 1) -> bool:
    """
    Atomically increment an admin alert stat counter.
    Keys live under hpe:stats:<field> and mirror hpe_admin_stats columns.
    Returns True on success, False when Redis is unavailable (caller falls
    back to PostgreSQL-only path — no data loss).
    """
    r = get_client()
    if r is None:
        return False
    try:
        r.incrby(_admin_key(field), amount)
        return True
    except Exception as exc:
        logger.debug(f"[Redis] admin INCRBY {field} failed: {exc}")
        return False


def admin_decr(field: str, amount: int = 1) -> bool:
    """
    Atomically decrement an admin alert stat counter (floor at 0).
    Used to reduce pending_count / critical_pending when an alert is resolved.
    """
    r = get_client()
    if r is None:
        return False
    try:
        # DECRBY then clamp to 0 to guard against counter drift
        new_val = r.decrby(_admin_key(field), amount)
        if new_val < 0:
            r.set(_admin_key(field), 0)
        return True
    except Exception as exc:
        logger.debug(f"[Redis] admin DECRBY {field} failed: {exc}")
        return False


def get_admin_stats() -> dict:
    """
    Read all admin alert counters in a single pipeline round-trip.
    Returns a populated dict when Redis is available, empty dict otherwise
    (caller must fall back to PostgreSQL COUNT queries).
    """
    r = get_client()
    if r is None:
        return {}
    try:
        pipe = r.pipeline(transaction=False)
        for field in ADMIN_STAT_KEYS:
            pipe.get(_admin_key(field))
        results = pipe.execute()

        counters = {}
        for i, field in enumerate(ADMIN_STAT_KEYS):
            raw = results[i]
            counters[field] = int(raw) if raw is not None else None  # None = key missing
        return counters
    except Exception as exc:
        logger.debug(f"[Redis] get_admin_stats failed: {exc}")
        return {}


def init_admin_stats_from_db(db_stats: dict) -> bool:
    """
    Seed Redis admin counters from the current PostgreSQL values.
    Called once at startup (main.py) so counters are accurate after a
    pod restart without waiting for events to rebuild them.
    Uses SET NX (only if not exists) to avoid resetting live counters
    when a second pod starts.
    """
    r = get_client()
    if r is None:
        return False
    try:
        pipe = r.pipeline(transaction=True)
        for field in ADMIN_STAT_KEYS:
            if field in db_stats and db_stats[field] is not None:
                pipe.setnx(_admin_key(field), int(db_stats[field]))
        pipe.execute()
        logger.info("[Redis] Admin stats seeded from PostgreSQL (SET NX)")
        return True
    except Exception as exc:
        logger.warning(f"[Redis] init_admin_stats_from_db failed: {exc}")
        return False
