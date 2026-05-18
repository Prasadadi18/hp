import hashlib
import time
import os
import uuid
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import db

logger = logging.getLogger("hpe.auth")
router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    department: str


def write_zeek_log(username: str, success: bool, request_ip: str):
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
    # We encode the username and status into the service field for threat_engine mapping
    service = f"auth_{username}_{status_str}"
    
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
    
    # Attempt to get real IP, fallback to simulated
    client_ip = http_req.client.host if http_req.client else "192.168.1.50"
    
    try:
        query = "SELECT * FROM hpe_users WHERE username = %s"
        user = db.execute_query(query, (request.username,), fetch=True)
        
        if not user:
            write_zeek_log(request.username, False, client_ip)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user.get('status') == 'pending':
            # Log as failure to Zeek to trigger pipeline visibility
            write_zeek_log(request.username, False, client_ip)
            raise HTTPException(status_code=403, detail="Account awaiting admin approval")
            
        if user['password_hash'] == pass_hash:
            # Reset failed attempts on success
            db.execute_query("UPDATE hpe_users SET failed_attempts = 0, last_login = NOW() WHERE username = %s", (request.username,))
            write_zeek_log(request.username, True, client_ip)
            return {"success": True, "message": "Login successful", "department": user['department']}
        else:
            # Increment failed attempts on failure
            db.execute_query("UPDATE hpe_users SET failed_attempts = failed_attempts + 1 WHERE username = %s", (request.username,))
            write_zeek_log(request.username, False, client_ip)
            raise HTTPException(status_code=401, detail="Invalid username or password")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error during login: {e}")
        # Even on DB error, write a failure Zeek log
        write_zeek_log(request.username, False, client_ip)
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

