"""
admin_store.py — PostgreSQL-backed store for admin alerts and audit trail.

Alert counters are mirrored in Redis (hpe:stats:*) for O(1) WebSocket reads.
Every mutation (create / approve / reject / auto-allow) increments/decrements
the relevant Redis counter atomically, then updates PostgreSQL as the source
of truth. get_stats() reads from Redis in a single pipeline call (microseconds)
and falls back to PostgreSQL COUNT(*) queries when Redis is unavailable.
"""

import logging
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app import db
from app import redis_client

logger = logging.getLogger("hpe.admin_store")


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

    query = """
        INSERT INTO hpe_admin_alerts (
            alert_id, event_id, user_id, threat_score, threat_action,
            xgb_score, lgb_score, ensemble_score, threshold,
            event_data, pipeline_stages, source_geo, destination_geo, total_latency_ms
        ) VALUES (
            %(alert_id)s, %(event_id)s, %(user_id)s, %(threat_score)s, %(threat_action)s,
            %(xgb_score)s, %(lgb_score)s, %(ensemble_score)s, %(threshold)s,
            %(event_data)s, %(pipeline_stages)s, %(source_geo)s, %(destination_geo)s, %(total_latency_ms)s
        )
    """
    
    params = {
        "alert_id": alert_id,
        "event_id": event_id,
        "user_id": user_id,
        "threat_score": threat_score,
        "threat_action": threat_action,
        "xgb_score": xgb_score,
        "lgb_score": lgb_score,
        "ensemble_score": ensemble_score,
        "threshold": threshold,
        "event_data": json.dumps(event_data),
        "pipeline_stages": json.dumps(pipeline_stages),
        "source_geo": json.dumps(source_geo),
        "destination_geo": json.dumps(destination_geo),
        "total_latency_ms": total_latency_ms,
    }
    
    try:
        db.execute_query(query, params)
        db.execute_query("UPDATE hpe_admin_stats SET total_alerts_created = total_alerts_created + 1 WHERE id = 1")
        # ── Redis atomic counters (best-effort, non-blocking) ──────────────
        redis_client.admin_incr("total_alerts")
        redis_client.admin_incr("total_alerts_created")
        redis_client.admin_incr("pending_count")
        if threat_action == "CRITICAL_ALERT":
            redis_client.admin_incr("critical_pending")
    except Exception as e:
        logger.error(f"Failed to create alert in DB: {e}")

    alert = get_alert(alert_id)
    logger.info(
        f"[ALERT] Created {alert_id} for user {user_id} "
        f"(score={threat_score:.4f}, action={threat_action})"
    )
    return alert


def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    """Get a single alert by ID."""
    query = "SELECT * FROM hpe_admin_alerts WHERE alert_id = %s"
    try:
        row = db.execute_query(query, (alert_id,), fetch=True)
        if row:
            if isinstance(row.get('event_data'), str):
                row['event_data'] = json.loads(row['event_data'])
            if isinstance(row.get('pipeline_stages'), str):
                row['pipeline_stages'] = json.loads(row['pipeline_stages'])
            if isinstance(row.get('source_geo'), str):
                row['source_geo'] = json.loads(row['source_geo'])
            if isinstance(row.get('destination_geo'), str):
                row['destination_geo'] = json.loads(row['destination_geo'])
            if isinstance(row.get('rotation_result'), str):
                row['rotation_result'] = json.loads(row['rotation_result'])
            if row.get('created_at'):
                row['created_at'] = row['created_at'].isoformat()
            if row.get('resolved_at'):
                row['resolved_at'] = row['resolved_at'].isoformat()
        return row
    except Exception as e:
        logger.error(f"Failed to get alert {alert_id}: {e}")
        return None


def get_all_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get alerts, optionally filtered by status and severity."""
    query = "SELECT * FROM hpe_admin_alerts WHERE 1=1"
    params = []

    if status:
        query += " AND status = %s"
        params.append(status)
    if severity:
        if severity == "critical":
            query += " AND threat_action = 'CRITICAL_ALERT'"
        elif severity == "high":
            query += " AND threat_action IN ('BLOCK', 'CRITICAL_ALERT')"
        elif severity == "medium":
            query += " AND threat_action = 'MONITOR'"

    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)

    try:
        rows = db.execute_query(query, tuple(params), fetch=True, fetch_all=True)
        alerts = []
        for row in rows:
            if isinstance(row.get('event_data'), str):
                row['event_data'] = json.loads(row['event_data'])
            if isinstance(row.get('pipeline_stages'), str):
                row['pipeline_stages'] = json.loads(row['pipeline_stages'])
            if isinstance(row.get('source_geo'), str):
                row['source_geo'] = json.loads(row['source_geo'])
            if isinstance(row.get('destination_geo'), str):
                row['destination_geo'] = json.loads(row['destination_geo'])
            if isinstance(row.get('rotation_result'), str):
                row['rotation_result'] = json.loads(row['rotation_result'])
            if row.get('created_at'):
                row['created_at'] = row['created_at'].isoformat()
            if row.get('resolved_at'):
                row['resolved_at'] = row['resolved_at'].isoformat()
            alerts.append(row)
        return alerts
    except Exception as e:
        logger.error(f"Failed to get all alerts: {e}")
        return []


def approve_alert(alert_id: str, admin_notes: str = "") -> Optional[Dict[str, Any]]:
    """Mark an alert as approved. Returns the alert or None if not found."""
    alert = get_alert(alert_id)
    if not alert:
        return None
    if alert["status"] != "pending":
        return alert

    try:
        query = """
            UPDATE hpe_admin_alerts 
            SET status = 'approved', resolved_at = NOW(), admin_notes = %s 
            WHERE alert_id = %s
        """
        db.execute_query(query, (admin_notes, alert_id))
        
        audit_query = """
            INSERT INTO hpe_admin_audit_log (action, alert_id, user_id, threat_score, admin_notes)
            VALUES ('approve', %s, %s, %s, %s)
        """
        db.execute_query(audit_query, (alert_id, alert["user_id"], alert["threat_score"], admin_notes))
        
        db.execute_query("UPDATE hpe_admin_stats SET total_approved = total_approved + 1 WHERE id = 1")
        # ── Redis atomic counters ──────────────────────────────────────────
        redis_client.admin_decr("pending_count")
        redis_client.admin_incr("total_approved")
        if alert.get("threat_action") == "CRITICAL_ALERT":
            redis_client.admin_decr("critical_pending")
    except Exception as e:
        logger.error(f"Failed to approve alert {alert_id}: {e}")
        return None

    logger.info(f"[ADMIN] Alert {alert_id} APPROVED for user {alert['user_id']}")
    return get_alert(alert_id)


def reject_alert(alert_id: str, admin_notes: str = "") -> Optional[Dict[str, Any]]:
    """Mark an alert as rejected (false positive). Returns the alert or None."""
    alert = get_alert(alert_id)
    if not alert:
        return None
    if alert["status"] != "pending":
        return alert

    try:
        query = """
            UPDATE hpe_admin_alerts 
            SET status = 'rejected', resolved_at = NOW(), admin_notes = %s 
            WHERE alert_id = %s
        """
        db.execute_query(query, (admin_notes, alert_id))
        
        audit_query = """
            INSERT INTO hpe_admin_audit_log (action, alert_id, user_id, threat_score, admin_notes)
            VALUES ('reject', %s, %s, %s, %s)
        """
        db.execute_query(audit_query, (alert_id, alert["user_id"], alert["threat_score"], admin_notes))
        
        db.execute_query("UPDATE hpe_admin_stats SET total_rejected = total_rejected + 1 WHERE id = 1")
        # ── Redis atomic counters ──────────────────────────────────────────
        redis_client.admin_decr("pending_count")
        redis_client.admin_incr("total_rejected")
        if alert.get("threat_action") == "CRITICAL_ALERT":
            redis_client.admin_decr("critical_pending")
    except Exception as e:
        logger.error(f"Failed to reject alert {alert_id}: {e}")
        return None

    logger.info(f"[ADMIN] Alert {alert_id} REJECTED (false positive)")
    return get_alert(alert_id)


def set_rotation_result(alert_id: str, rotation_result: Dict[str, Any]):
    """Attach the Vault rotation result to an approved alert."""
    try:
        query = "UPDATE hpe_admin_alerts SET rotation_result = %s WHERE alert_id = %s"
        db.execute_query(query, (json.dumps(rotation_result), alert_id))
    except Exception as e:
        logger.error(f"Failed to set rotation result for {alert_id}: {e}")


def increment_auto_allowed():
    """Track events that were auto-allowed (low threat score)."""
    try:
        db.execute_query("UPDATE hpe_admin_stats SET total_auto_allowed = total_auto_allowed + 1 WHERE id = 1")
        # ── Redis atomic counter ───────────────────────────────────────────
        redis_client.admin_incr("total_auto_allowed")
    except Exception as e:
        logger.error(f"Failed to increment auto allowed: {e}")


def get_stats() -> Dict[str, Any]:
    """
    Get admin dashboard summary stats.

    Fast path (Redis): single pipeline GET across all hpe:stats:* keys —
    returns in microseconds regardless of N admin clients or pod count.

    Slow path (PostgreSQL fallback): used when Redis is unavailable or the
    keys have not been seeded yet (e.g. first startup before any events).
    """
    # ── 1. Try Redis first ────────────────────────────────────────────────
    try:
        redis_stats = redis_client.get_admin_stats()
        # All keys must be present and non-None for the Redis read to be valid.
        # A None value means the key has never been written (cold start), so
        # we fall through to PostgreSQL to seed the counters accurately.
        if redis_stats and all(v is not None for v in redis_stats.values()):
            return {
                "total_alerts_created": redis_stats.get("total_alerts_created", 0),
                "total_approved":       redis_stats.get("total_approved", 0),
                "total_rejected":       redis_stats.get("total_rejected", 0),
                "total_auto_allowed":   redis_stats.get("total_auto_allowed", 0),
                "pending_count":        redis_stats.get("pending_count", 0),
                "critical_pending":     redis_stats.get("critical_pending", 0),
                "total_alerts":         redis_stats.get("total_alerts", 0),
                "_source": "redis",
            }
    except Exception as e:
        logger.debug(f"[Stats] Redis read failed, falling back to PG: {e}")

    # ── 2. PostgreSQL fallback ────────────────────────────────────────────
    try:
        stats_row = db.execute_query("SELECT * FROM hpe_admin_stats WHERE id = 1", fetch=True)
        if not stats_row:
             stats_row = {
                 "total_alerts_created": 0,
                 "total_approved": 0,
                 "total_rejected": 0,
                 "total_auto_allowed": 0
             }
             
        pending_row = db.execute_query("SELECT COUNT(*) as count FROM hpe_admin_alerts WHERE status = 'pending'", fetch=True)
        pending_count = pending_row['count'] if pending_row else 0
        
        critical_row = db.execute_query("SELECT COUNT(*) as count FROM hpe_admin_alerts WHERE status = 'pending' AND threat_action = 'CRITICAL_ALERT'", fetch=True)
        critical_pending = critical_row['count'] if critical_row else 0
        
        total_row = db.execute_query("SELECT COUNT(*) as count FROM hpe_admin_alerts", fetch=True)
        total_alerts = total_row['count'] if total_row else 0

        result = {
            "total_alerts_created": stats_row.get("total_alerts_created", 0),
            "total_approved":       stats_row.get("total_approved", 0),
            "total_rejected":       stats_row.get("total_rejected", 0),
            "total_auto_allowed":   stats_row.get("total_auto_allowed", 0),
            "pending_count":        pending_count,
            "critical_pending":     critical_pending,
            "total_alerts":         total_alerts,
            "_source": "postgres",
        }

        # Opportunistically seed Redis so next call is fast
        redis_client.init_admin_stats_from_db(result)
        return result

    except Exception as e:
        logger.error(f"Failed to get admin stats: {e}")
        return {
            "total_alerts_created": 0,
            "total_approved": 0,
            "total_rejected": 0,
            "total_auto_allowed": 0,
            "pending_count": 0,
            "critical_pending": 0,
            "total_alerts": 0,
            "_source": "error",
        }


def get_audit_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Get the audit log of admin actions, newest first."""
    try:
        query = "SELECT * FROM hpe_admin_audit_log ORDER BY timestamp DESC LIMIT %s"
        rows = db.execute_query(query, (limit,), fetch=True, fetch_all=True)
        for row in rows:
            if row.get('timestamp'):
                row['timestamp'] = row['timestamp'].isoformat()
        return rows
    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        return []

def load_from_db():
    pass

