import hashlib
import json
import time
import os
import uuid
import logging
import asyncio
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import db
from app import vault_client
from app.schemas import NetworkEvent, PredictionResult
from app.threat_engine import process_event

logger = logging.getLogger("hpe.auth")
router = APIRouter()

# ── Shared Redis Client (lazy-init, graceful fallback) ────────────────────────
# Used for cross-pod caching of user profile rows and VPN lookup results.
# If Redis is unavailable the code degrades transparently to direct DB / HTTP.
try:
    import redis as _redis_lib
except ImportError:
    _redis_lib = None  # type: ignore

_redis_client = None
_redis_initialized = False
_redis_lock = threading.Lock()


def _get_redis():
    """Return a shared Redis client, or None when Redis is unavailable."""
    global _redis_client, _redis_initialized
    if _redis_initialized:
        return _redis_client
    with _redis_lock:
        if _redis_initialized:
            return _redis_client
        if _redis_lib is None:
            logger.warning("[Auth] redis-py not installed — caching disabled")
            _redis_initialized = True
            return None
        try:
            redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
            client = _redis_lib.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
            client.ping()
            _redis_client = client
            logger.info(f"[Auth] Redis connected at {redis_url}")
        except Exception as e:
            logger.warning(f"[Auth] Redis unavailable ({e}) — caching disabled")
            _redis_client = None
        _redis_initialized = True
    return _redis_client


# ── User-Profile Cache (Redis) ────────────────────────────────────────────────
# Key:  user:{username}
# Value: JSON-encoded row from hpe_users (username, department, status,
#        password_hash, failed_attempts, last_login, last_login_region,
#        last_login_ip, last_failed_attempt)
# TTL:  300 s  (5 minutes)
_USER_CACHE_TTL = 300


def _cache_key_user(username: str) -> str:
    return f"user:{username}"


def get_cached_user(username: str) -> Optional[dict]:
    """Return cached hpe_users row, or None on miss / Redis down."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_cache_key_user(username))
        if raw:
            return json.loads(raw)
    except Exception as e:
        logger.debug(f"[Auth] Redis GET user:{username} failed: {e}")
    return None


def cache_user(username: str, user_row: dict) -> None:
    """Store hpe_users row in Redis. Serialises datetime fields to ISO strings."""
    r = _get_redis()
    if r is None:
        return
    try:
        # Make row JSON-serialisable (datetimes → ISO strings)
        serialisable = {}
        for k, v in user_row.items():
            if isinstance(v, datetime):
                serialisable[k] = v.isoformat()
            else:
                serialisable[k] = v
        r.setex(_cache_key_user(username), _USER_CACHE_TTL, json.dumps(serialisable))
        logger.debug(f"[Auth] Cached user:{username} (TTL={_USER_CACHE_TTL}s)")
    except Exception as e:
        logger.debug(f"[Auth] Redis SET user:{username} failed: {e}")


def invalidate_user_cache(username: str) -> None:
    """Delete the cached user row so the next request re-reads from PostgreSQL."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.delete(_cache_key_user(username))
        logger.debug(f"[Auth] Invalidated cache for user:{username}")
    except Exception as e:
        logger.debug(f"[Auth] Redis DEL user:{username} failed: {e}")


def _restore_user_datetimes(user: dict) -> dict:
    """Convert ISO-string datetime fields back to datetime objects after cache hit."""
    dt_fields = ("last_login", "last_failed_attempt")
    for field in dt_fields:
        val = user.get(field)
        if isinstance(val, str):
            try:
                user[field] = datetime.fromisoformat(val)
            except Exception:
                user[field] = None
    return user

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    department: str

# Window within which a region change since the last login counts as
# impossible travel (you cannot physically relocate regions this fast).
IMPOSSIBLE_TRAVEL_WINDOW_SECONDS = 6 * 3600


# ── VPN / Proxy IP Detection ─────────────────────────────────────────────────
# Uses ip-api.com (free, 45 req/min) to detect VPN, proxy, and hosting IPs.
#
# Two-level cache:
#   L1 – per-process dict (_vpn_cache)  → ~0 ms, no network
#   L2 – shared Redis key vpn:{ip}      → shared across all replicas
# Results stored in both layers on a cold fetch from ip-api.com.
_vpn_cache: dict = {}
_vpn_cache_lock = threading.Lock()
_VPN_CACHE_TTL = 600  # 10 minutes
_VPN_REDIS_KEY_PREFIX = "vpn:"


def _cache_key_vpn(ip: str) -> str:
    return f"{_VPN_REDIS_KEY_PREFIX}{ip}"


def check_vpn_ip(ip: str) -> dict:
    """
    Check if an IP address belongs to a VPN, proxy, or hosting provider.
    Returns dict with: is_vpn, isp, country, city, region.
    Uses ip-api.com free tier (45 req/min, no key needed).

    Cache hierarchy:
      1. In-process dict (L1) — checked first, no I/O
      2. Shared Redis key vpn:{ip} (L2) — shared across replicas, TTL=600s
      3. Live ip-api.com HTTP call — result written to both cache layers
    """
    # Skip private/docker IPs — always return immediately, nothing to cache.
    if ip.startswith(("10.", "172.", "192.168.", "127.", "0.")):
        return {"is_vpn": False, "isp": "Private Network", "country": "Local", "city": "Local", "region": "Local"}

    # ── L1: in-process cache ──────────────────────────────────────────────────
    with _vpn_cache_lock:
        cached = _vpn_cache.get(ip)
        if cached and (time.time() - cached.get("_ts", 0)) < _VPN_CACHE_TTL:
            logger.debug(f"[Auth] VPN L1 hit for {ip}")
            return cached

    # ── L2: shared Redis cache ────────────────────────────────────────────────
    r = _get_redis()
    if r is not None:
        try:
            raw = r.get(_cache_key_vpn(ip))
            if raw:
                result = json.loads(raw)
                result["_ts"] = time.time()  # refresh local timestamp
                with _vpn_cache_lock:
                    _vpn_cache[ip] = result
                logger.debug(f"[Auth] VPN L2 (Redis) hit for {ip}")
                return result
        except Exception as e:
            logger.debug(f"[Auth] Redis GET vpn:{ip} failed: {e}")

    # ── L3: live HTTP lookup ──────────────────────────────────────────────────
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,country,city,regionName"
        req = urllib.request.Request(url, headers={"User-Agent": "HPE-ThreatPipeline/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") != "success":
            logger.warning(f"ip-api.com lookup failed for {ip}: {data}")
            return {"is_vpn": False, "isp": "Unknown", "country": "Unknown", "city": "Unknown", "region": "Unknown"}

        result = {
            "is_vpn": bool(data.get("proxy") or data.get("hosting")),
            "isp": data.get("isp", "Unknown"),
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "_ts": time.time(),
        }

        # Write to L1 (in-process dict)
        with _vpn_cache_lock:
            _vpn_cache[ip] = result
            # Prune L1 cache if it grows too large
            if len(_vpn_cache) > 500:
                oldest = sorted(_vpn_cache.items(), key=lambda x: x[1].get("_ts", 0))[:100]
                for k, _ in oldest:
                    del _vpn_cache[k]

        # Write to L2 (Redis) — strip internal _ts field so it doesn't age in Redis
        if r is not None:
            try:
                redis_payload = {k: v for k, v in result.items() if k != "_ts"}
                r.setex(_cache_key_vpn(ip), _VPN_CACHE_TTL, json.dumps(redis_payload))
                logger.debug(f"[Auth] VPN cached in Redis for {ip} (TTL={_VPN_CACHE_TTL}s)")
            except Exception as e:
                logger.debug(f"[Auth] Redis SET vpn:{ip} failed: {e}")

        logger.info(f"VPN check for {ip}: is_vpn={result['is_vpn']}, isp={result['isp']}, country={result['country']}")
        return result

    except Exception as e:
        logger.warning(f"VPN IP check failed for {ip}: {e}")
        # Fallback: use the legacy IP-prefix heuristic
        is_vpn_fallback = ip.startswith(("45.", "82.", "185.", "104.", "198."))
        return {"is_vpn": is_vpn_fallback, "isp": "Unknown", "country": "Unknown", "city": "Unknown", "region": "Unknown"}


def _broadcast_vpn_alert(username: str, client_ip: str, vpn_info: dict, login_success: bool):
    """Immediately broadcast a VPN login alert to the dashboard via WebSocket."""
    from app.ws_manager import manager as ws_manager, admin_manager

    alert_data = {
        "type": "vpn_login_alert",
        "data": {
            "username": username,
            "source_ip": client_ip,
            "vpn_provider": vpn_info.get("isp", "Unknown VPN"),
            "country": vpn_info.get("country", "Unknown"),
            "city": vpn_info.get("city", "Unknown"),
            "region": vpn_info.get("region", "Unknown"),
            "login_success": login_success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }

    try:
        # Broadcast to BOTH simulation dashboard and admin panel using sync-safe methods
        ws_manager.broadcast_sync(alert_data)
        admin_manager.broadcast_sync(alert_data)
        logger.info(f"🛡️ VPN LOGIN ALERT broadcast: {username} from {client_ip} ({vpn_info.get('isp')})")
    except Exception as e:
        logger.warning(f"Failed to broadcast VPN login alert: {e}")

    # Email the security admin on VPN detection (replaces the old per-CRITICAL
    # email flood — VPN logins are far lower volume).
    try:
        from app.soar_email import send_vpn_alert_email
        send_vpn_alert_email(username, client_ip, vpn_info, login_success)
    except Exception as e:
        logger.warning(f"Failed to send VPN alert email: {e}")


def write_zeek_log(username: str, success: bool, request_ip: str, is_vpn: bool = False):
    """Write login attempt as a Zeek TSV log line to be picked up by Filebeat."""
    log_path = os.environ.get("ZEEK_LOG_PATH", "/shared-data/zeek-live/conn.log")
    
    # Format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes
    ts = f"{time.time():.6f}"
    uid = f"C{uuid.uuid4().hex[:12]}"
    orig_h = request_ip
    orig_p = "12345"
    resp_h = "10.0.0.1"  # The server
    resp_p = "443"
    proto = "tcp"
    
    status_str = "success" if success else "failure"
    # Encode username, status, and VPN flag into service field for threat_engine mapping
    # Format: auth_{username}_{status}_vpn (if VPN detected)
    service = f"auth_{username}_{status_str}"
    if is_vpn:
        service += "_vpn"
    
    # Mock some data for the remaining fields
    duration = "1.0"
    orig_bytes = "500"
    resp_bytes = "500" if success else "100"
    conn_state = "SF" if success else "REJ"
    
    # 20 fields total to match the Filebeat config dissect tokenizer
    tsv_line = f"{ts}\t{uid}\t{orig_h}\t{orig_p}\t{resp_h}\t{resp_p}\t{proto}\t{service}\t{duration}\t{orig_bytes}\t{resp_bytes}\t{conn_state}\t-\t-\t0\tShADadFf\t10\t1000\t10\t1000\n"
    
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(tsv_line)
        logger.info(f"Wrote login event to Zeek log: {service}")
    except Exception as e:
        logger.error(f"Failed to write to Zeek log at {log_path}: {e}")

@router.post("/login")
def login(request: LoginRequest, http_req: Request):
    # Hash password using simple sha256 for demo
    pass_hash = hashlib.sha256(request.password.encode('utf-8')).hexdigest()
    
    # Attempt to get real IP from proxy headers, fallback to client host
    client_ip = http_req.headers.get("x-forwarded-for") or (http_req.client.host if http_req.client else "192.168.1.50")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # ── Real-time VPN Detection ───────────────────────────────────────────────
    vpn_info = check_vpn_ip(client_ip)
    is_vpn = vpn_info.get("is_vpn", False)
    if is_vpn:
        logger.warning(f"🛡️ VPN DETECTED: User '{request.username}' logging in from VPN IP {client_ip} ({vpn_info.get('isp')}, {vpn_info.get('country')})")
    
    try:
        # ── Redis L1: try cached user profile first (skip PostgreSQL on HIT) ─
        user = get_cached_user(request.username)
        cache_hit = user is not None
        if cache_hit:
            user = _restore_user_datetimes(user)
            logger.debug(f"[Auth] user:{request.username} served from Redis cache")
        else:
            query = "SELECT * FROM hpe_users WHERE username = %s"
            user = db.execute_query(query, (request.username,), fetch=True)
            if user:
                cache_user(request.username, user)

        if not user:
            write_zeek_log(request.username, False, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user.get('status') == 'pending':
            # Log as failure to Zeek to trigger pipeline visibility
            write_zeek_log(request.username, False, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
            raise HTTPException(status_code=403, detail="Account awaiting admin approval")
            
        if user['password_hash'] == pass_hash:
            # Capture login memory BEFORE resetting — the accumulated failed
            # attempts and previous session info are returned to the frontend.
            prev_failed_attempts = user.get('failed_attempts') or 0
            prev_last_login = user.get('last_login')
            prev_last_region = user.get('last_login_region')
            prev_last_failed = user.get('last_failed_attempt')

            # Brute-force lockout: a successful login that immediately follows
            # more than 5 failed attempts inside the 5-minute window is treated
            # as a likely credential-stuffing success — rotate the credentials
            # right away so the attacker's password is invalidated.
            brute_force_login = False
            if prev_failed_attempts > 5 and prev_last_failed:
                try:
                    elapsed = (datetime.now(timezone.utc) - prev_last_failed).total_seconds()
                    brute_force_login = elapsed < 300
                except Exception:
                    brute_force_login = False

            # Get role and user_id
            profile = next((p for p in vault_client._user_profiles if p.get("user_id") == request.username), None)
            dept_to_role = {
                "Engineering": "Developer",
                "Finance": "Finance",
                "HR": "HR",
                "Sales": "Sales",
                "Security": "Admin"
            }
            role = profile.get("role") if profile else dept_to_role.get(user['department'], "Employee")
            home_region = (profile or {}).get("home_region", "US-East")

            # Reset failed attempts and record this session. A fresh login
            # always starts at the clean HOME baseline — stale regions from
            # earlier simulations must never leak into a new session. Region
            # memory only moves within a session, via simulations.
            try:
                db.execute_query(
                    "UPDATE hpe_users SET failed_attempts = 0, last_login = NOW(), "
                    "last_login_ip = %s, last_login_region = %s "
                    "WHERE username = %s",
                    (client_ip, home_region, request.username)
                )
            except Exception as mem_err:
                # Memory columns may not exist on an un-migrated DB — degrade gracefully
                logger.warning(f"Login memory update failed (falling back): {mem_err}")
                db.execute_query("UPDATE hpe_users SET failed_attempts = 0, last_login = NOW() WHERE username = %s", (request.username,))
            # Invalidate cache — the row has just been mutated
            invalidate_user_cache(request.username)

            write_zeek_log(request.username, True, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=True)

            # ── Brute-force auto-rotation ──────────────────────────────────────
            # Rotate immediately on the suspicious login. rotate_credentials()
            # also emails the new password to the security admin and resets the
            # account's login memory. The portal's session watcher detects the
            # change within seconds and locks the workspace.
            credentials_rotated = False
            if brute_force_login:
                try:
                    rot = vault_client.rotate_credentials(
                        reason=f"brute_force_login_{prev_failed_attempts}_fails_in_5min",
                        user=request.username,
                        threat_score=0.99,
                    )
                    credentials_rotated = bool(rot.get("success"))
                    logger.warning(
                        f"[BRUTE-FORCE] {request.username} logged in after "
                        f"{prev_failed_attempts} failed attempts within 5 min — "
                        f"credentials auto-rotated (success={credentials_rotated})"
                    )
                except Exception as rot_err:
                    logger.error(f"Brute-force rotation failed for {request.username}: {rot_err}")

            return {
                "success": True,
                "message": "Login successful",
                "department": user['department'],
                "user_id": request.username,
                "role": role,
                "failed_attempts": prev_failed_attempts,
                "last_login": prev_last_login.isoformat() if prev_last_login else None,
                "last_login_region": home_region,
                "credentials_rotated": credentials_rotated,
                "security_notice": (
                    f"Account was accessed after {prev_failed_attempts} failed attempts in 5 minutes. "
                    "Credentials have been rotated for your protection."
                ) if credentials_rotated else None
            }
        else:
            # Increment failed attempts within a rolling 5-minute window: if the
            # last failure was over 5 minutes ago, the burst is stale — start a
            # new window at 1. Otherwise keep counting up.
            try:
                db.execute_query(
                    "UPDATE hpe_users SET "
                    "failed_attempts = CASE WHEN last_failed_attempt > NOW() - INTERVAL '5 minutes' "
                    "                       THEN failed_attempts + 1 ELSE 1 END, "
                    "last_failed_attempt = NOW() "
                    "WHERE username = %s",
                    (request.username,)
                )
            except Exception as fa_err:
                logger.warning(f"Windowed failed-attempt update failed (falling back): {fa_err}")
                db.execute_query("UPDATE hpe_users SET failed_attempts = failed_attempts + 1 WHERE username = %s", (request.username,))
            # Invalidate cache — failed_attempts counter has changed
            invalidate_user_cache(request.username)
            write_zeek_log(request.username, False, client_ip, is_vpn)
            if is_vpn:
                _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
            raise HTTPException(status_code=401, detail="Invalid username or password")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during login: {e}")
        # Even on DB error, write a failure Zeek log
        write_zeek_log(request.username, False, client_ip, is_vpn)
        if is_vpn:
            _broadcast_vpn_alert(request.username, client_ip, vpn_info, login_success=False)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/register")
def register(request: RegisterRequest):
    try:
        # Check if user already exists
        query = "SELECT * FROM hpe_users WHERE username = %s"
        existing = db.execute_query(query, (request.username,), fetch=True)
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
            
        # Insert user with status='pending' and no password hash yet
        insert_query = "INSERT INTO hpe_users (username, department, status) VALUES (%s, %s, 'pending')"
        db.execute_query(insert_query, (request.username, request.department))
        
        # Broadcast to admin WebSocket connection
        from app.ws_manager import admin_manager
        import asyncio
        from datetime import datetime, timezone
        
        is_vpn = ("vpn" in request.username.lower() or "vpn" in request.department.lower())
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    admin_manager.broadcast({
                        "type": "new_registration",
                        "data": {
                            "username": request.username,
                            "department": request.department,
                            "status": "pending",
                            "is_vpn": is_vpn,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    }),
                    loop
                )
        except Exception as e:
            logger.warning(f"Failed to broadcast live registration: {e}")

        return {"success": True, "message": "Access request submitted. Awaiting admin approval and credential issuance."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during registration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


class SimulateRequest(BaseModel):
    username: str
    password: str
    login_hour: Optional[int] = None
    ip_region: Optional[str] = None
    data_downloaded_mb: Optional[float] = None
    failed_attempts: Optional[int] = None
    impossible_travel: Optional[bool] = None
    is_vpn: Optional[bool] = None


@router.post("/simulate")
def simulate(request: SimulateRequest, http_req: Request):
    # Hash password using sha256 to verify against database
    pass_hash = hashlib.sha256(request.password.encode('utf-8')).hexdigest()
    
    # Get client real IP
    client_ip = http_req.headers.get("x-forwarded-for") or (http_req.client.host if http_req.client else "192.168.1.50")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
        
    try:
        # 1. Authenticate user (Redis cache → PostgreSQL fallback)
        user = get_cached_user(request.username)
        if user is not None:
            user = _restore_user_datetimes(user)
            logger.debug(f"[Auth/simulate] user:{request.username} served from Redis cache")
        else:
            query = "SELECT * FROM hpe_users WHERE username = %s"
            user = db.execute_query(query, (request.username,), fetch=True)
            if user:
                cache_user(request.username, user)

        # Bypass password check for simulation to allow easy script execution
        # if not user or user['password_hash'] != pass_hash:
        #     raise HTTPException(status_code=401, detail="Invalid username or password")

        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user.get('status') == 'pending':
            raise HTTPException(status_code=403, detail="Account awaiting admin approval")

        # 2. Load user baseline profile
        profile = next((p for p in vault_client._user_profiles if p.get("user_id") == request.username), None)
        if not profile:
            profile = {
                "user_id": request.username,
                "role": "Developer",
                "base_login_hour": 9,
                "login_hour_std_dev": 2.0,
                "avg_daily_downloads_mb": 50.0,
                "home_region": "US-East",
                "remote_worker": False,
                "is_shift_worker": False,
                "clumsiness_factor": 0.05
            }

        # 3. Handle features and overrides
        home_region = profile.get("home_region", "US-East")
        selected_ip_region = request.ip_region if request.ip_region else home_region
        geo_mismatch = (selected_ip_region != home_region)
        
        selected_hour = request.login_hour if request.login_hour is not None else datetime.now(timezone.utc).hour
        selected_downloads = request.data_downloaded_mb if request.data_downloaded_mb is not None else profile.get("avg_daily_downloads_mb", 10.0)
        selected_failed = request.failed_attempts if request.failed_attempts is not None else (user.get('failed_attempts') or 0)
        is_vpn = bool(request.is_vpn)

        # Impossible travel: explicit override wins; otherwise auto-detect from
        # login memory — the user picked a different region than their previous
        # login within a window too short to physically relocate.
        prev_region = user.get('last_login_region')
        prev_login = user.get('last_login')
        if request.impossible_travel is not None:
            impossible_travel = bool(request.impossible_travel)
        else:
            impossible_travel = False
            if prev_region and prev_login and prev_region != selected_ip_region:
                try:
                    elapsed = (datetime.now(timezone.utc) - prev_login).total_seconds()
                    impossible_travel = elapsed < IMPOSSIBLE_TRAVEL_WINDOW_SECONDS
                except Exception:
                    pass
        
        # Determine anomaly flag and type
        # VPN alone from home region is NOT an anomaly (per Fix #3)
        # Only flag as anomaly when VPN is combined with suspicious behavior
        is_anomaly = False
        anomaly_type = "None"
        
        if impossible_travel:
            is_anomaly = True
            anomaly_type = "Impossible Travel"
        elif geo_mismatch and is_vpn:
            is_anomaly = True
            anomaly_type = "VPN with Geographic Anomaly"
        elif geo_mismatch:
            is_anomaly = True
            anomaly_type = "Geographic Anomaly"
        elif selected_downloads > 200:
            is_anomaly = True
            anomaly_type = "Data Exfiltration"
        elif selected_failed > 3:
            is_anomaly = True
            anomaly_type = "Credential Stuffing"
        # VPN alone without geo_mismatch or other anomalies is NOT flagged as anomaly

        # 4. Construct NetworkEvent
        event_dict = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "login_hour": selected_hour,
            "user_id": request.username,
            "workspace_id": "WS-SIM-001",
            "source_ip": client_ip,
            "ip_region": selected_ip_region,
            "user_region": home_region,
            "geo_mismatch": geo_mismatch,
            "impossible_travel": impossible_travel,
            "action": "login",
            "success": True,
            "failed_attempts_last_15m": selected_failed,
            "data_downloaded_mb": selected_downloads,
            "role": profile.get("role", "Developer"),
            "remote_worker": profile.get("remote_worker", False),
            "base_login_hour": profile.get("base_login_hour", 9.0),
            "login_hour_std_dev": profile.get("login_hour_std_dev", 2.0),
            "avg_daily_downloads_mb": profile.get("avg_daily_downloads_mb", 50.0),
            "home_region": home_region,
            "is_shift_worker": profile.get("is_shift_worker", False),
            "clumsiness_factor": profile.get("clumsiness_factor", 0.0),
            "is_injected_anomaly": is_anomaly,
            "anomaly_type": anomaly_type,
            "event_source": "threat_simulation_portal",
            "is_vpn": is_vpn
        }
        
        event = NetworkEvent(**event_dict)
        
        # 5. Process event directly through threat engine (forcing rotation on BLOCK/CRITICAL)
        result = process_event(event, force_rotation=True)
        
        # 6. Write Zeek log for pipeline visibility
        write_zeek_log(request.username, True, client_ip, is_vpn)

        # 7. Add credentials rotated flags to output
        result_data = result.model_dump()

        rotation_stage = next((s for s in result.pipeline_stages if s.stage_name == "HashiCorp Vault"), None)
        rotated = False
        new_password = None

        if rotation_stage and rotation_stage.status == "rotated":
            rotated = True
            new_password = vault_client.get_user_login_password_cleartext(request.username)

        # 7b. Update login memory.
        #  - No rotation: the simulation becomes the latest access, so the next
        #    region change from here can be flagged as impossible travel.
        #  - Rotation: the incident is resolved and the account re-secured —
        #    reset to a clean baseline (home region, zero failures) so the
        #    next login does NOT inherit the attacker's session state.
        try:
            if rotated:
                db.execute_query(
                    "UPDATE hpe_users SET last_login = NOW(), last_login_region = %s, failed_attempts = 0 WHERE username = %s",
                    (home_region, request.username)
                )
            else:
                db.execute_query(
                    "UPDATE hpe_users SET last_login = NOW(), last_login_region = %s WHERE username = %s",
                    (selected_ip_region, request.username)
                )
            # Invalidate cache — login_region / failed_attempts may have changed
            invalidate_user_cache(request.username)
        except Exception as mem_err:
            logger.warning(f"Simulation login memory update failed: {mem_err}")
            
        result_data["credentials_rotated"] = rotated
        if rotated and new_password:
            result_data["new_password"] = new_password
            
        return result_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during threat simulation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Curated demo accounts whose passwords are visible in the credential helper.
# All other users are listed but their passwords are masked on the frontend.
DEMO_USER_IDS = ["USR-0001", "USR-0002", "USR-0005"]


@router.get("/demo-users")
def get_demo_users():
    """Return the demo user IDs whose passwords may be shown in the helper."""
    return {"demo_users": DEMO_USER_IDS}


@router.get("/login-history/{user_id}")
def get_login_history(user_id: str):
    """Login memory for a user: last session time, region, IP, and failure count."""
    try:
        user = db.execute_query(
            "SELECT last_login, last_login_region, last_login_ip, failed_attempts FROM hpe_users WHERE username = %s",
            (user_id,), fetch=True
        )
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        last_login = user.get('last_login')
        return {
            "user_id": user_id,
            "last_login": last_login.isoformat() if last_login else None,
            "last_login_region": user.get('last_login_region'),
            "last_login_ip": user.get('last_login_ip'),
            "failed_attempts": user.get('failed_attempts') or 0
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching login history for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users")
def get_users():
    try:
        query = "SELECT username, department FROM hpe_users WHERE status = 'active'"
        users = db.execute_query(query, fetch=True, fetch_all=True)
        if not users:
            return []
        
        dept_to_role = {
            "Engineering": "Developer",
            "Finance": "Finance",
            "HR": "HR",
            "Sales": "Sales",
            "Security": "Admin"
        }
        
        results = []
        for u in users:
            uname = u["username"]
            dept = u["department"]
            profile = next((p for p in vault_client._user_profiles if p.get("user_id") == uname), None)
            role = profile.get("role") if profile else dept_to_role.get(dept, "Employee")
            results.append({
                "user_id": uname,
                "role": role
            })
        results.sort(key=lambda x: x["user_id"])
        return results
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/user-profile/{user_id}")
def get_user_profile(user_id: str):
    try:
        profile = next((p for p in vault_client._user_profiles if p.get("user_id") == user_id), None)
        if profile:
            return profile
        
        query = "SELECT * FROM hpe_users WHERE username = %s"
        user = db.execute_query(query, (user_id,), fetch=True)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        dept_to_role = {
            "Engineering": "Developer",
            "Finance": "Finance",
            "HR": "HR",
            "Sales": "Sales",
            "Security": "Admin"
        }
        
        return {
            "user_id": user_id,
            "role": dept_to_role.get(user["department"], "Employee"),
            "base_login_hour": 9,
            "login_hour_std_dev": 2.0,
            "avg_daily_downloads_mb": 10.0,
            "clumsiness_factor": 0.05,
            "num_known_devices": 1,
            "remote_worker": False,
            "home_region": "US-East",
            "travel_probability": 0.01,
            "is_shift_worker": False
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user profile for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/user-credential/{user_id}")
def get_user_credential(user_id: str):
    try:
        password = vault_client.get_user_login_password_cleartext(user_id)
        if not password:
            if user_id in ["alice", "bob", "charlie", "admin"]:
                return {"user_id": user_id, "current_password": "password123"}
            raise HTTPException(status_code=404, detail="Credentials not found in Vault")
        return {"user_id": user_id, "current_password": password}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reading credential from Vault for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

