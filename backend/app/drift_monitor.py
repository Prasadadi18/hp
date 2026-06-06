import logging
import asyncio
import urllib.request
import json
from typing import Optional
from app import elastic_client, vault_client, config

logger = logging.getLogger("hpe.drift_monitor")

# Configurable constants
DRIFT_CHECK_INTERVAL_SECONDS = 300  # Check every 5 minutes
FPR_THRESHOLD = 0.15                # 15% false positive rate threshold
MIN_RESOLVED_ALERTS = 3             # Minimum alerts before checking drift

def _send_dispatch(url: str, headers: dict, payload: dict):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.status, response.read()

async def check_model_drift_and_trigger():
    """Query ES for recent resolutions and trigger GitHub retraining if drift is detected."""
    if not elastic_client.is_connected() or not elastic_client._es:
        logger.warning("[Drift Monitor] Elasticsearch not connected — skipping check")
        return

    try:
        # Search for threats resolved by admin
        res = elastic_client._es.search(
            index="hpe-threats",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "resolution"}}
                        ]
                    }
                },
                "size": 100
            }
        )
        hits = res.get("hits", {}).get("hits", [])
        if not hits:
            logger.info("[Drift Monitor] No resolved threat records found in ES")
            return

        total_resolved = len(hits)
        false_positives = sum(1 for h in hits if h["_source"].get("resolution") == "rejected")
        true_positives = total_resolved - false_positives

        fpr = false_positives / total_resolved if total_resolved > 0 else 0.0
        logger.info(
            f"[Drift Monitor] Checked drift: TP={true_positives}, FP={false_positives}, "
            f"FPR={fpr:.4f} (Threshold={FPR_THRESHOLD})"
        )

        if total_resolved >= MIN_RESOLVED_ALERTS and fpr > FPR_THRESHOLD:
            logger.warning(
                f"[Drift Monitor] ALERT: Drift detected! FPR={fpr:.4f} > {FPR_THRESHOLD}. "
                f"Triggering automated retraining via GitHub Actions..."
            )
            await trigger_github_retraining(fpr, total_resolved)
    except Exception as e:
        logger.error(f"[Drift Monitor] Error during drift evaluation: {e}")

async def trigger_github_retraining(fpr: float, total_alerts: int):
    """Trigger the GitHub Action workflow via repository dispatch."""
    token = vault_client.get_github_pat()
    if not token:
        logger.error("[Drift Monitor] GITHUB_PAT not found in Vault or Environment — cannot trigger retraining")
        return

    repo = config.GITHUB_REPO
    url = f"https://api.github.com/repos/{repo}/dispatches"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "FastAPI-Drift-Monitor"
    }

    payload = {
        "event_type": "ml_drift_detected",
        "client_payload": {
            "false_positive_rate": round(fpr, 4),
            "total_alerts": total_alerts,
            "message": f"Automated drift detection: FPR={fpr:.4f} exceeded threshold of {FPR_THRESHOLD}."
        }
    }

    try:
        status, body = await asyncio.to_thread(_send_dispatch, url, headers, payload)
        if status in (200, 204):
            logger.warning("[Drift Monitor] Successfully triggered GitHub retraining workflow!")
        else:
            logger.error(
                f"[Drift Monitor] Failed to trigger GitHub retraining. "
                f"Status={status}, Response={body.decode('utf-8')}"
            )
    except Exception as e:
        logger.error(f"[Drift Monitor] Exception while contacting GitHub: {e}")

async def drift_monitor_loop():
    """Infinitely loop in the background checking for drift."""
    logger.info("[Drift Monitor] Starting background monitoring loop")
    # Wait a bit on startup for services to initialize
    await asyncio.sleep(10)
    while True:
        await check_model_drift_and_trigger()
        await asyncio.sleep(DRIFT_CHECK_INTERVAL_SECONDS)
