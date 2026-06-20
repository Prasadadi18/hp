"""
routes/health.py — Health check and metrics endpoints.
"""

import time
from fastapi import APIRouter
from app.schemas import HealthResponse, MetricsResponse
from app.config import APP_NAME, APP_VERSION
from app import kafka_client, elastic_client
from app import vault_client, inference, redis_client
from app.threat_engine import get_metrics

router = APIRouter(prefix="/api", tags=["health"])

_start_time = time.time()


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Check health of all pipeline components."""
    metrics = get_metrics()
    return HealthResponse(
        status="healthy",
        app_name=APP_NAME,
        version=APP_VERSION,
        uptime_seconds=round(time.time() - _start_time, 1),
        model_loaded=inference.get_artifacts() is not None,
        kafka_connected=kafka_client.is_connected(),
        elasticsearch_connected=elastic_client.is_connected(),
        vault_connected=vault_client.is_connected(),
        redis_connected=redis_client.is_available(),
        total_requests=metrics["total_requests"],
        total_threats_blocked=(
            metrics["total_blocked"] + metrics["total_critical"]
        ),
    )


@router.get("/metrics", response_model=MetricsResponse)
def get_pipeline_metrics():
    """Get detailed pipeline metrics."""
    metrics = get_metrics()
    redis_up = redis_client.is_available()
    return MetricsResponse(
        total_requests=metrics["total_requests"],
        total_threats=metrics["total_threats"],
        total_allowed=metrics["total_allowed"],
        total_monitored=metrics["total_monitored"],
        total_blocked=metrics["total_blocked"],
        total_critical=metrics["total_critical"],
        avg_latency_ms=metrics["avg_latency_ms"],
        model_metrics=metrics.get("model_metrics", {}),
        pipeline_health={
            "kafka": (
                "connected" if kafka_client.is_connected() else "disconnected"
            ),
            "elasticsearch": (
                "connected"
                if elastic_client.is_connected()
                else "disconnected"
            ),
            "vault": (
                "connected" if vault_client.is_connected() else "disconnected"
            ),
            "model": ("loaded" if inference.get_artifacts() else "not_loaded"),
            "redis": ("connected" if redis_up else "disconnected"),
        },
        attack_types=metrics.get("attack_types", {}),
        source=metrics.get("source", "db_fallback"),
        redis_connected=redis_up,
    )


@router.get("/vault/credentials")
def get_vault_credentials():
    """Get current Vault credentials (masked) for frontend display."""
    return vault_client.get_visible_credentials()


@router.get("/vault/users")
def get_all_vault_users(role: str = None, region: str = None):
    """
    Get masked credentials for ALL 200 users stored in Vault.
    Optional query params: ?role=Developer&region=US-East
    """
    all_creds = vault_client.get_all_user_credentials()

    if role:
        all_creds = [
            c for c in all_creds if c.get("role", "").lower() == role.lower()
        ]
    if region:
        all_creds = [
            c
            for c in all_creds
            if c.get("home_region", "").lower() == region.lower()
        ]
    return {
        "total_users": len(all_creds),
        "global_rotation_count": vault_client.get_rotation_count(),
        "users": all_creds,
    }


@router.get("/vault/users/{user_id}")
def get_vault_user(user_id: str):
    """Get masked credentials for a specific user from Vault."""
    return vault_client.get_user_credentials(user_id)


@router.get("/kafka/stats")
async def get_kafka_stats():
    """Get real Kafka topic metadata, partition offsets, and consumer group lag."""
    return kafka_client.get_topic_stats()


@router.get("/elasticsearch/recent-threats")
def get_recent_threats(size: int = 20):
    """Fetch recent threat detections from Elasticsearch."""
    threats = elastic_client.search_recent_threats(size=size)
    return {
        "total": len(threats),
        "threats": threats,
    }


@router.get("/elasticsearch/stats")
def get_es_stats():
    """Get aggregated threat statistics from Elasticsearch."""
    stats = elastic_client.get_threat_stats()
    # Also get index document counts
    doc_counts = {}
    if elastic_client.is_connected() and elastic_client._es:
        try:
            for idx in ["hpe-audit-logs", "hpe-threats"]:
                count = elastic_client._es.count(index=idx)
                doc_counts[idx] = count.get("count", 0)
        except Exception:
            pass
    return {
        "connected": elastic_client.is_connected(),
        "threat_breakdown": stats,
        "index_doc_counts": doc_counts,
    }
