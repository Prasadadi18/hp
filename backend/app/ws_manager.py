"""
ws_manager.py — WebSocket connection managers for simulation and admin streams.
"""

import json
import logging
from fastapi import WebSocket
from typing import List

logger = logging.getLogger("hpe.ws")


class ConnectionManager:
    """Manages a set of WebSocket connections and broadcasts messages."""

    def __init__(self, name: str = "default"):
        self.name = name
        self.connections: List[WebSocket] = []

    def add(self, ws: WebSocket):
        self.connections.append(ws)
        logger.info(f"[WS:{self.name}] Client connected ({len(self.connections)} active)")

    def remove(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)
        logger.info(f"[WS:{self.name}] Client disconnected ({len(self.connections)} active)")

    async def broadcast(self, data: dict):
        """Send a JSON message to all connected clients."""
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.remove(ws)

    @property
    def active_count(self) -> int:
        return len(self.connections)


# Simulation stream (existing)
manager = ConnectionManager("simulation")

# Admin alert stream (new)
admin_manager = ConnectionManager("admin")
