"""
admin_store.py — In-memory store for admin alerts and audit trail.
Thread-safe alert queue for pending threat approvals.
"""

import logging
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import OrderedDict

logger = logging.getLogger("hpe.admin_store")

_lock = threading.Lock()

# Ordered dict preserves insertion order — newest alerts appear last
_alerts: OrderedDict[str, Dict[str, Any]] = OrderedDict()

# Audit log of all admin actions (approve/reject)
_audit_log: List[Dict[str, Any]] = []

# Stats
_stats = {
    "total_alerts_created": 0,
    "total_approved": 0,
    "total_rejected": 0,
    "total_auto_allowed": 0,
}


def create_alert(
    event_id: str,
    user_id: str,
    threat_score: float,
    threat_action: str,
    xgb_score: float,
    lgb_score: float,
    ensemble_score: float,
    threshold: float,
    event_data: Dict[str, Any],
    pipeline_stages: List[Dict[str, Any]],
    source_geo: Dict[str, Any],
    destination_geo: Dict[str, Any],
    total_latency_ms: float,
) -> Dict[str, Any]:
    """Create a new pending admin alert for a detected threat."""
    alert_id = f"ALR-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id": alert_id,
        "event_id": event_id,
        "user_id": user_id,
        "threat_score": threat_score,
        "threat_action": threat_action,
        "xgb_score": xgb_score,
        "lgb_score": lgb_score,
        "ensemble_score": ensemble_score,
        "threshold": threshold,
        "event_data": event_data,
        "pipeline_stages": pipeline_stages,
        "source_geo": source_geo,
        "destination_geo": destination_geo,
        "total_latency_ms": total_latency_ms,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "resolved_at": None,
        "resolved_by": "admin",
        "admin_notes": "",
        "rotation_result": None,
    }

    with _lock:
        _alerts[alert_id] = alert
        _stats["total_alerts_created"] += 1

    logger.info(
        f"[ALERT] Created {alert_id} for user {user_id} "
        f"(score={threat_score:.4f}, action={threat_action})"
    )
    return alert


def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    """Get a single alert by ID."""
    with _lock:
        return _alerts.get(alert_id)


def get_all_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get alerts, optionally filtered by status and severity."""
    with _lock:
        alerts = list(_alerts.values())

    # Filter
    if status:
        alerts = [a for a in alerts if a["status"] == status]
    if severity:
        if severity == "critical":
            alerts = [a for a in alerts if a["threat_action"] == "CRITICAL_ALERT"]
        elif severity == "high":
            alerts = [a for a in alerts if a["threat_action"] in ("BLOCK", "CRITICAL_ALERT")]
        elif severity == "medium":
            alerts = [a for a in alerts if a["threat_action"] == "MONITOR"]

    # Return newest first, limited
    alerts.reverse()
    return alerts[:limit]


def approve_alert(alert_id: str, admin_notes: str = "") -> Optional[Dict[str, Any]]:
    """Mark an alert as approved. Returns the alert or None if not found."""
    with _lock:
        alert = _alerts.get(alert_id)
        if not alert:
            return None
        if alert["status"] != "pending":
            return alert  # Already resolved

        alert["status"] = "approved"
        alert["resolved_at"] = datetime.now(timezone.utc).isoformat()
        alert["admin_notes"] = admin_notes
        _stats["total_approved"] += 1

        # Add to audit log
        _audit_log.append({
            "action": "approve",
            "alert_id": alert_id,
            "user_id": alert["user_id"],
            "threat_score": alert["threat_score"],
            "admin_notes": admin_notes,
            "timestamp": alert["resolved_at"],
        })

    logger.info(f"[ADMIN] Alert {alert_id} APPROVED for user {alert['user_id']}")
    return alert


def reject_alert(alert_id: str, admin_notes: str = "") -> Optional[Dict[str, Any]]:
    """Mark an alert as rejected (false positive). Returns the alert or None."""
    with _lock:
        alert = _alerts.get(alert_id)
        if not alert:
            return None
        if alert["status"] != "pending":
            return alert

        alert["status"] = "rejected"
        alert["resolved_at"] = datetime.now(timezone.utc).isoformat()
        alert["admin_notes"] = admin_notes
        _stats["total_rejected"] += 1

        _audit_log.append({
            "action": "reject",
            "alert_id": alert_id,
            "user_id": alert["user_id"],
            "threat_score": alert["threat_score"],
            "admin_notes": admin_notes,
            "timestamp": alert["resolved_at"],
        })

    logger.info(f"[ADMIN] Alert {alert_id} REJECTED (false positive)")
    return alert


def set_rotation_result(alert_id: str, rotation_result: Dict[str, Any]):
    """Attach the Vault rotation result to an approved alert."""
    with _lock:
        alert = _alerts.get(alert_id)
        if alert:
            alert["rotation_result"] = rotation_result


def increment_auto_allowed():
    """Track events that were auto-allowed (low threat score)."""
    with _lock:
        _stats["total_auto_allowed"] += 1


def get_stats() -> Dict[str, Any]:
    """Get admin dashboard summary stats."""
    with _lock:
        pending_count = sum(1 for a in _alerts.values() if a["status"] == "pending")
        critical_pending = sum(
            1 for a in _alerts.values()
            if a["status"] == "pending" and a["threat_action"] == "CRITICAL_ALERT"
        )
        return {
            **_stats,
            "pending_count": pending_count,
            "critical_pending": critical_pending,
            "total_alerts": len(_alerts),
        }


def get_audit_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Get the audit log of admin actions, newest first."""
    with _lock:
        return list(reversed(_audit_log[-limit:]))
