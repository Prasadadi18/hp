"""
routes/admin.py — Security Admin Dashboard API endpoints.
Phase 4: CRITICAL_ALERT approval triggers BOTH user-level AND
         infrastructure credential rotation.
         BLOCK approval triggers user-level rotation only.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.schemas import ApprovalRequest, ApprovalResponse
from app import admin_store, vault_client, vault_infra_client
from app.ws_manager import admin_manager

logger = logging.getLogger("hpe.admin")
router = APIRouter(prefix="/api/admin", tags=["admin"])


def _determine_affected_service(event_data: dict) -> str:
    """
    Map the anomaly type to the infrastructure service most at risk.
    Called only for CRITICAL_ALERT approvals.

    Logic:
    - data_exfiltration / bulk_download  → elasticsearch  (attacker querying audit logs)
    - lateral_movement / priv_escalation → kafka          (attacker injecting fake events)
    - admin action                        → database       (rotate the DB service account)
    - default                             → elasticsearch  (protect the audit trail)
    """
    anomaly = event_data.get("anomaly_type", "None")
    action = event_data.get("action", "")

    if anomaly in ["data_exfiltration", "bulk_download"]:
        return "elasticsearch"
    elif anomaly in ["lateral_movement", "privilege_escalation"]:
        return "kafka"
    elif action == "admin":
        return "database"
    else:
        return "elasticsearch"


@router.get("/alerts")
async def get_alerts(status: str = None, severity: str = None, limit: int = 100):
    """
    List all admin alerts.
    Query params: ?status=pending|approved|rejected&severity=critical|high|medium&limit=100
    """
    alerts = admin_store.get_all_alerts(status=status, severity=severity, limit=limit)
    pending_count = sum(1 for a in admin_store.get_all_alerts(status="pending"))
    return {
        "total": len(alerts),
        "pending_count": pending_count,
        "alerts": alerts,
    }


@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Get full forensic details for a single alert."""
    alert = admin_store.get_alert(alert_id)
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    return alert


@router.post("/alerts/{alert_id}/approve", response_model=ApprovalResponse)
async def approve_alert(alert_id: str, request: ApprovalRequest):
    """
    Approve credential rotation for a threat alert.

    Rotation strategy based on threat level:
      BLOCK threat       → user-level rotation only
                           vault_client.rotate_credentials(user=...)

      CRITICAL_ALERT     → user-level rotation PLUS infrastructure rotation
                           vault_client.rotate_credentials(user=...)
                           vault_infra_client.rotate_infrastructure_credentials(service=...)

    This is proportionate response — CRITICAL threats get both layers rotated
    because at score > 0.85, the attacker may have already pivoted from the
    user account to the service infrastructure.
    """
    alert = admin_store.approve_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="approve",
            message=f"Alert {alert_id} not found",
        )

    if alert["status"] != "approved":
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="approve",
            message=f"Alert already resolved as: {alert['status']}",
        )

    # ── User-level rotation (fires for ALL approvals: BLOCK + CRITICAL) ───────
    user_rotation_result = vault_client.rotate_credentials(
        reason=f"admin_approved_{alert['threat_action'].lower()}_score_{alert['threat_score']:.4f}",
        user=alert["user_id"],
        threat_score=alert["threat_score"],
    )

    logger.info(
        f"[ADMIN] User credential rotation for {alert['user_id']} "
        f"(alert={alert_id}, success={user_rotation_result.get('success')}, "
        f"action={alert['threat_action']})"
    )

    # ── Infrastructure rotation (fires ONLY for CRITICAL_ALERT) ──────────────
    infra_rotation_result = None
    affected_service = None

    if alert["threat_action"] == "CRITICAL_ALERT":
        if vault_infra_client.is_connected():
            affected_service = _determine_affected_service(alert.get("event_data", {}))
            infra_rotation_result = vault_infra_client.rotate_infrastructure_credentials(
                service=affected_service,
                reason=f"admin_approved_critical_score_{alert['threat_score']:.4f}",
                threat_score=alert["threat_score"],
            )
            logger.warning(
                f"[ADMIN] Infrastructure credential rotation for service='{affected_service}' "
                f"(alert={alert_id}, "
                f"new_user='{infra_rotation_result.get('new_credential', {}).get('username', 'n/a')}', "
                f"success={infra_rotation_result.get('success')})"
            )
        else:
            logger.warning(
                f"[ADMIN] Vault infra client not connected — "
                f"skipping infrastructure rotation for CRITICAL_ALERT {alert_id}"
            )
            infra_rotation_result = {
                "success": False,
                "error": "vault_infra_client not connected",
            }
    else:
        # BLOCK threat — infra rotation not triggered (proportionate response)
        logger.info(
            f"[ADMIN] BLOCK threat approved — user rotation only, "
            f"no infrastructure rotation (score={alert['threat_score']:.4f} < 0.85 threshold)"
        )

    # ── Attach combined result to alert for audit trail ───────────────────────
    combined_result = {
        "user_rotation": user_rotation_result,
        "infra_rotation": infra_rotation_result,
        "affected_service": affected_service,
        "threat_action": alert["threat_action"],
    }
    admin_store.set_rotation_result(alert_id, combined_result)

    # ── Broadcast to admin WebSocket clients ──────────────────────────────────
    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id": alert_id,
            "action": "approved",
            "user_id": alert["user_id"],
            "threat_action": alert["threat_action"],
            "user_rotation_success": user_rotation_result.get("success", False),
            "infra_rotation": infra_rotation_result,
            "affected_service": affected_service,
        },
    })

    # ── Build response message ────────────────────────────────────────────────
    message_parts = [f"User credentials rotated for {alert['user_id']}."]
    if infra_rotation_result and infra_rotation_result.get("success"):
        new_user = infra_rotation_result.get("new_credential", {}).get("username", "")
        message_parts.append(
            f"Infrastructure credentials rotated for '{affected_service}' "
            f"(new DB user: {new_user[:20]}...)."
        )
    elif alert["threat_action"] == "CRITICAL_ALERT" and infra_rotation_result:
        message_parts.append(
            f"Infrastructure rotation attempted for '{affected_service}' "
            f"but failed: {infra_rotation_result.get('error', 'unknown error')}."
        )

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="approved",
        rotation_result=combined_result,
        message=" ".join(message_parts),
    )


@router.post("/alerts/{alert_id}/reject", response_model=ApprovalResponse)
async def reject_alert(alert_id: str, request: ApprovalRequest):
    """Reject an alert as a false positive. No credential rotation of any kind."""
    alert = admin_store.reject_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="reject",
            message=f"Alert {alert_id} not found",
        )

    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id": alert_id,
            "action": "rejected",
            "user_id": alert["user_id"],
        },
    })

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="rejected",
        message=f"Alert {alert_id} rejected as false positive. No credentials rotated.",
    )


@router.get("/stats")
async def get_admin_stats():
    """Get admin dashboard summary statistics including infra rotation count."""
    stats = admin_store.get_stats()
    stats["infra_rotation_count"] = vault_infra_client.get_infra_rotation_count()
    stats["active_infra_leases"] = vault_infra_client.get_active_leases()
    return stats


@router.get("/audit-log")
async def get_audit_log(limit: int = 50):
    """Get the history of all admin actions."""
    log = admin_store.get_audit_log(limit=limit)
    return {"total": len(log), "entries": log}


@router.get("/infra-leases")
async def get_infra_leases():
    """
    Get all currently active Vault infrastructure leases.
    Shows which PostgreSQL service users are live, their TTL, and expiry time.
    Useful for verifying infrastructure rotation worked correctly.
    """
    return {
        "active_leases": vault_infra_client.get_active_leases(),
        "total_infra_rotations": vault_infra_client.get_infra_rotation_count(),
        "vault_infra_connected": vault_infra_client.is_connected(),
    }


# ── Admin WebSocket for real-time alert notifications ─────────────────────────
@router.websocket("/ws")
async def admin_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time admin alert push notifications."""
    await websocket.accept()
    admin_manager.add(websocket)

    # Send current state on connect so admin dashboard initialises correctly
    stats = admin_store.get_stats()
    stats["infra_rotation_count"] = vault_infra_client.get_infra_rotation_count()
    await websocket.send_json({
        "type": "admin_connected",
        "data": stats,
    })

    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        admin_manager.remove(websocket)
    except Exception as e:
        admin_manager.remove(websocket)
        logger.error(f"Admin WebSocket error: {e}")