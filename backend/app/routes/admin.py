"""
routes/admin.py — Security Admin Dashboard API endpoints.
Provides alert management, approval workflow, and admin audit log.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.schemas import ApprovalRequest, ApprovalResponse
from app import admin_store, vault_client
from app.ws_manager import admin_manager

logger = logging.getLogger("hpe.admin")
router = APIRouter(prefix="/api/admin", tags=["admin"])


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
    This triggers the actual Vault credential rotation.
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

    # Execute the actual Vault credential rotation
    rotation_result = vault_client.rotate_credentials(
        reason=f"admin_approved_threat_score_{alert['threat_score']:.4f}",
        user=alert["user_id"],
        threat_score=alert["threat_score"],
    )

    # Attach rotation result to the alert
    admin_store.set_rotation_result(alert_id, rotation_result)

    logger.info(
        f"[ADMIN] Credential rotation executed for {alert['user_id']} "
        f"(alert={alert_id}, vault_success={rotation_result.get('success')})"
    )

    # Broadcast to admin WebSocket clients
    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id": alert_id,
            "action": "approved",
            "user_id": alert["user_id"],
            "rotation_success": rotation_result.get("success", False),
        },
    })

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="approved",
        rotation_result=rotation_result,
        message=f"Credentials rotated for {alert['user_id']}",
    )


@router.post("/alerts/{alert_id}/reject", response_model=ApprovalResponse)
async def reject_alert(alert_id: str, request: ApprovalRequest):
    """Reject an alert as a false positive. No credential rotation."""
    alert = admin_store.reject_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="reject",
            message=f"Alert {alert_id} not found",
        )

    # Broadcast to admin WebSocket clients
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
        message=f"Alert {alert_id} rejected as false positive",
    )


@router.get("/stats")
async def get_admin_stats():
    """Get admin dashboard summary statistics."""
    return admin_store.get_stats()


@router.get("/audit-log")
async def get_audit_log(limit: int = 50):
    """Get the history of all admin actions."""
    log = admin_store.get_audit_log(limit=limit)
    return {"total": len(log), "entries": log}


# ── Admin WebSocket for real-time alert notifications ──────────────────────────
@router.websocket("/ws")
async def admin_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time admin alert notifications."""
    await websocket.accept()
    admin_manager.add(websocket)

    # Send current stats on connect
    stats = admin_store.get_stats()
    await websocket.send_json({
        "type": "admin_connected",
        "data": stats,
    })

    try:
        while True:
            # Keep alive — listen for any messages from admin client
            data = await websocket.receive_text()
            # Could handle admin commands here in the future
    except WebSocketDisconnect:
        admin_manager.remove(websocket)
    except Exception as e:
        admin_manager.remove(websocket)
        logger.error(f"Admin WebSocket error: {e}")
