"""
NetVision — WebSocket live feed (api/websocket.py)

WS /ws/live

Pushes a JSON message to all connected clients every 500ms containing:
  • Latest N packets (default 20)
  • Current stats snapshot
  • Any new alerts since the last push

Clients can send a JSON message to configure the subscription:
  { "packet_limit": 50 }

Connection lifecycle
────────────────────
  Client connects → added to manager
  Push loop runs until client disconnects or server shuts down
  Client disconnect → removed from manager silently
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.api.state import capture_engine, stats_engine, anomaly_detector

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

# How often to push updates (seconds)
PUSH_INTERVAL = 0.5


class ConnectionManager:
    """Manages the set of active WebSocket connections."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("WS client connected. Total: %d", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.remove(ws)
        logger.info("WS client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, data: dict) -> None:
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                self._connections.remove(ws)
            except ValueError:
                pass


manager = ConnectionManager()

# Track the last alert timestamp we've sent so we only push NEW alerts
_last_alert_push_time: float = 0.0


@router.websocket("/ws/live")
async def live_feed(ws: WebSocket):
    """
    Real-time packet, stats, and alert feed over WebSocket.
    """
    global _last_alert_push_time

    await manager.connect(ws)
    packet_limit = 20  # Default packets per push

    try:
        while True:
            # Honour incoming config messages (non-blocking)
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=0.01)
                msg = json.loads(raw)
                if "packet_limit" in msg:
                    packet_limit = max(1, min(int(msg["packet_limit"]), 200))
            except (asyncio.TimeoutError, json.JSONDecodeError):
                pass
            except WebSocketDisconnect:
                break

            # Build the push payload
            now = time.time()

            # Recent packets
            recent_pkts = capture_engine.get_recent_packets(limit=packet_limit)
            packets_payload = [p.to_dict() for p in reversed(recent_pkts)]

            # Stats snapshot
            snap = stats_engine.latest_snapshot()
            stats_payload = snap.to_dict() if snap else None

            # New alerts since last push
            all_alerts = anomaly_detector.get_alerts(limit=500)
            new_alerts = [
                a.to_dict() for a in all_alerts
                if a.timestamp > _last_alert_push_time
            ]
            if all_alerts:
                _last_alert_push_time = all_alerts[0].timestamp

            payload = {
                "type": "live_update",
                "timestamp": now,
                "packets": packets_payload,
                "stats": stats_payload,
                "new_alerts": new_alerts,
                "capture_running": capture_engine.is_running,
            }

            try:
                await ws.send_json(payload)
            except WebSocketDisconnect:
                break
            except Exception as exc:
                logger.debug("WS send error: %s", exc)
                break

            await asyncio.sleep(PUSH_INTERVAL)

    except WebSocketDisconnect:
        pass
    finally:
        try:
            manager.disconnect(ws)
        except ValueError:
            pass
