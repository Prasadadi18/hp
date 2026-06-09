"""
routes/predict.py — Prediction endpoints for single and batch event inference.
"""

from fastapi import APIRouter, HTTPException
from typing import List
from app.schemas import NetworkEvent, PredictionResult, BatchPredictRequest
from app.threat_engine import process_event
from app import kafka_client
from app import config

router = APIRouter(prefix="/api", tags=["prediction"])


@router.get("/test-soar-email")
async def test_soar_email():
    """
    Diagnostic endpoint: sends a test SOAR alert email synchronously.
    Returns success/error so we can debug email issues inside the container.
    """
    from app.soar_email import _send_email
    import traceback

    diag = {
        "soar_enabled": config.SOAR_EMAIL_ENABLED,
        "sender": config.SOAR_SENDER_EMAIL,
        "receiver": config.SOAR_RECEIVER_EMAIL,
        "smtp_host": config.SOAR_SMTP_HOST,
        "smtp_port": config.SOAR_SMTP_PORT,
        "password_length": len(config.SOAR_SENDER_PASSWORD),
    }

    if not config.SOAR_EMAIL_ENABLED:
        return {**diag, "status": "DISABLED", "message": "SOAR_EMAIL_ENABLED is false"}

    try:
        _send_email(
            event_id="DIAG-TEST-001",
            user="diagnostic_test",
            source_ip="10.0.0.99",
            threat_score=0.95,
            action="BLOCK",
            reasons=["Diagnostic test from /api/test-soar-email endpoint"],
        )
        return {**diag, "status": "SUCCESS", "message": f"Email sent to {config.SOAR_RECEIVER_EMAIL}"}
    except Exception as e:
        return {**diag, "status": "FAILED", "error": str(e), "traceback": traceback.format_exc()}


@router.post("/predict", response_model=PredictionResult)
async def predict_event(event: NetworkEvent):
    """
    Process a single network event through the full pipeline.
    Returns prediction result with all pipeline stage details.
    """
    try:
        result = process_event(event)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")


@router.post("/ingest")
async def ingest_event(event: NetworkEvent):
    """
    Async ingestion — produces to Kafka.
    Result will be broadcast via WebSocket when the consumer processes it.
    """
    success = kafka_client.produce_raw_event(event.model_dump())
    kafka_client.flush()
    return {"status": "queued" if success else "kafka_unavailable"}



@router.post("/batch", response_model=List[PredictionResult])
async def batch_predict(request: BatchPredictRequest):
    """
    Process multiple network events through the pipeline.
    """
    if len(request.events) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 events per batch")

    results = []
    for event in request.events:
        try:
            result = process_event(event)
            results.append(result)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Batch prediction error: {str(e)}")

    return results
