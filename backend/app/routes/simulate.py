"""
simulate.py — WebSocket endpoint to stream test events to the frontend.
Maintains a global event index so the simulation continues from where it
left off even when the frontend reconnects.
"""

import json
import os
import time
import asyncio
import random
import logging
from pathlib import Path
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.config import TEST_EVENTS_PATH, PORTAL_ONLY_MODE
from app.schemas import NetworkEvent
from app.threat_engine import process_event
from app import kafka_client
from app import db
from app.ws_manager import manager as ws_manager

logger = logging.getLogger("hpe.simulate")
router = APIRouter(tags=["simulation"])

# In-memory cache for test events
_test_events = None

# Global simulation position — persists across frontend reconnects
_sim_index = 0
_sim_batch_count = 0
_SIM_BATCH_SIZE = 10

def _load_sim_index():
    global _sim_index
    try:
        row = db.execute_query("SELECT sim_index FROM hpe_simulation_state WHERE id = 1", fetch=True)
        if row:
            _sim_index = row.get("sim_index", 0)
    except Exception as e:
        logger.error(f"Failed to load sim_index: {e}")

def _save_sim_index():
    global _sim_index, _sim_batch_count
    _sim_batch_count += 1
    if _sim_batch_count >= _SIM_BATCH_SIZE:
        try:
            db.execute_query("UPDATE hpe_simulation_state SET sim_index = %s WHERE id = 1", (_sim_index,))
            _sim_batch_count = 0
        except Exception as e:
            logger.error(f"Failed to save sim_index: {e}")

def reset_simulation_state():
    """Reset simulation index to 0 (called on pipeline reset)."""
    global _sim_index, _sim_batch_count
    _sim_index = 0
    _sim_batch_count = 0
    logger.info("[Simulate] Simulation state reset to index 0")

def _load_test_events():
    global _test_events
    path = Path(TEST_EVENTS_PATH)
    if not path.exists():
        logger.error(f"Test events file not found: {TEST_EVENTS_PATH}")
        _test_events = []
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            _test_events = json.load(f)
        logger.info(f"Loaded {len(_test_events)} test events for simulation")
    except Exception as e:
        logger.error(f"Failed to load test events: {e}")
        _test_events = []

# ── Single shared producer ────────────────────────────────────────────────────
# There is exactly ONE producer task for the whole backend, regardless of how
# many dashboards/tabs are connected. Each /ws/simulate connection used to run
# its OWN producer loop, so every browser refresh spawned another producer (the
# old one only died on its next heartbeat send) and the event rate compounded
# (~+60 events/refresh). Now connections only *receive* ws_manager broadcasts;
# this task is the sole producer and runs only while ≥1 dashboard is connected.
_producer_task = None
_producer_start_lock = asyncio.Lock()


async def _ensure_producer_started():
    """Start the shared producer if it isn't already running."""
    global _producer_task
    async with _producer_start_lock:
        if _producer_task is None or _producer_task.done():
            _producer_task = asyncio.create_task(_producer_loop())
            logger.info("Started shared simulation producer")


async def _producer_loop():
    """The single source of synthetic events. Streams labelled test_events into
    Kafka (or processes locally + broadcasts when Kafka is down). Stops itself
    once no dashboards remain connected."""
    global _sim_index
    if _test_events is None:
        _load_test_events()
    _load_sim_index()
    total = len(_test_events)
    if total == 0:
        return

    while ws_manager.active_count > 0:
        try:
            # Optional: pause while an external Zeek live-replay is actively
            # writing (off by default — the labelled stream is what shows real
            # users/scores). Enable with SUPPRESS_SIM_DURING_REPLAY=true.
            if os.environ.get("SUPPRESS_SIM_DURING_REPLAY", "").lower() == "true":
                log_path = os.environ.get("ZEEK_LOG_PATH", "/app/dataset/zeek-live/conn.log")
                if os.path.exists(log_path):
                    try:
                        if time.time() - os.path.getmtime(log_path) < 10:
                            await asyncio.sleep(2.0)
                            continue
                    except Exception:
                        pass

            raw_event = _test_events[_sim_index % total]

            if kafka_client.is_connected():
                kafka_client.produce_raw_event({
                    "event_id": str(uuid.uuid4())[:12],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **raw_event,
                })
                kafka_client.flush()
            else:
                # Kafka down: run the pipeline inline and broadcast to all clients.
                event = NetworkEvent(**{k: v for k, v in raw_event.items()
                                        if k in NetworkEvent.model_fields})
                result = process_event(event)
                await ws_manager.broadcast({
                    "type": "pipeline_result",
                    "data": {"event": raw_event, "prediction": result.model_dump()},
                })

            _sim_index += 1
            _save_sim_index()
            if _sim_index > 0 and _sim_index % total == 0:
                logger.info(f"Simulation completed cycle {_sim_index // total}, looping...")

        except Exception as e:
            logger.error(f"Simulation producer error: {e}")

        # ~2 events/sec
        await asyncio.sleep(0.5)

    logger.info("No dashboards connected — shared simulation producer stopped")


@router.websocket("/ws/simulate")
async def simulate_stream(websocket: WebSocket):
    """
    WebSocket endpoint for the dashboard. It only RECEIVES events (via
    ws_manager broadcasts from the Kafka consumer or the shared producer);
    it does not produce. The shared producer is started on first connection.
    """
    global _sim_index
    await websocket.accept()

    if _test_events is None:
        _load_test_events()
    _load_sim_index()

    total = len(_test_events)

    # Send server info + where the simulation currently is.
    await websocket.send_json({
        "type": "server_info",
        "data": {"lat": 12.97, "lng": 77.59, "city": "Bangalore"},
    })
    await websocket.send_json({
        "type": "simulation_status",
        "data": {
            "resuming_from": _sim_index,
            "total_events": total,
            "message": f"Resuming simulation from event {_sim_index}/{total}",
        },
    })

    # Register to receive broadcasts (Kafka-consumer results + producer output).
    ws_manager.add(websocket)

    # Start the single shared producer if we have a dataset to stream. In
    # portal-only mode (total == 0) there's no synthetic dataset — the
    # connection still stays open to receive REAL portal/login events.
    if total > 0 and not PORTAL_ONLY_MODE:
        await _ensure_producer_started()

    # This connection never produces; just stay registered until it disconnects.
    try:
        while True:
            raw_event = _test_events[_sim_index % total]

            try:
                if kafka_client.is_connected():
                    kafka_client.produce_raw_event({
                        "event_id": str(uuid.uuid4())[:12],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        **raw_event,
                    })
                    kafka_client.flush()  # Ensure delivery
                else:
                    # Fallback if Kafka is down
                    event = NetworkEvent(**{k: v for k, v in raw_event.items()
                                        if k in NetworkEvent.model_fields})
                    result = process_event(event)

                    # Send the full result
                    await websocket.send_json({
                        "type": "pipeline_result",
                        "data": {
                            "event": raw_event,
                            "prediction": result.model_dump(),
                        }
                    })

            except Exception as e:
                logger.error(f"Simulation event error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": str(e)},
                })

            # Advance global position
            _sim_index += 1
            _save_sim_index()

            # Log when a full cycle completes
            if _sim_index > 0 and _sim_index % total == 0:
                logger.info(f"Simulation completed cycle {_sim_index // total}, looping...")

            # Random delay between events (2.0s - 5.0s)
            delay = random.uniform(2.0, 5.0)
            await asyncio.sleep(delay)

            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.remove(websocket)
        logger.info(f"Simulation client disconnected (position {_sim_index})")
    except Exception as e:
        ws_manager.remove(websocket)
        logger.error(f"Simulate WS error: {e}")

@router.get("/api/sample-events")
async def get_sample_events():
    """Get the loaded sample events (for frontend initialization)."""
    if _test_events is None:
        _load_test_events()

    return {
        "test_events_count": len(_test_events)
    }
