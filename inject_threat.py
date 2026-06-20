import asyncio
from app.threat_engine import process_event
from app.schemas import NetworkEvent

event_dict = {
    "event_id": "SIM-999",
    "timestamp": "2026-06-19T12:00:00Z",
    "login_hour": 3,
    "user_id": "USR-0001",
    "workspace_id": "WS-SIM-001",
    "source_ip": "185.15.2.1",
    "ip_region": "Asia-Pacific",
    "user_region": "US-East",
    "geo_mismatch": True,
    "impossible_travel": True,
    "action": "login",
    "success": False,
    "failed_attempts_last_15m": 6,
    "data_downloaded_mb": 500.0,
    "role": "Developer",
    "remote_worker": False,
    "base_login_hour": 9.0,
    "login_hour_std_dev": 2.0,
    "avg_daily_downloads_mb": 50.0,
    "home_region": "US-East",
    "is_shift_worker": False,
    "clumsiness_factor": 0.0,
    "is_injected_anomaly": True,
    "anomaly_type": "Impossible Travel",
    "event_source": "live_portal",
    "is_vpn": True
}

event = NetworkEvent(**event_dict)
print("Injecting Live Portal threat event...")
res = process_event(event, force_rotation=True)
print("Threat action:", res.threat_action)
print("Score:", res.threat_score)
