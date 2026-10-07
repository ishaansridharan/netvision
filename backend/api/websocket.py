"""
NetVision — WebSocket live feed (api/websocket.py)

WS /ws/live

Pushes a JSON message to each client every 500 ms containing:
  • packets captured since that client's last push (up to packet_limit)
  • the latest stats snapshot (only when a new one exists)
  • alerts raised since that client's last push
  • capture status and pipeline metrics

Per-client cursors
──────────────────
Each connection remembers the last packet seq and alert seq it was sent.
(A single global "last pushed" timestamp would make the second client miss
every alert the first one had already received.)

Clients can send JSON to configure the subscription:
  { "packet_limit": 50 }     packets per push (1–500)
  { "packets": false }       pause the packet stream (e.g. Dashboard view)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.api.state import anomaly_detector, capture_engine, stats_engine

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

PUSH_INTERVAL = 0.5


class _ClientState:
    def __init__(self) -> None:
        self.packet_limit = 50
        self.want_packets = True
        # Start from "now": a new client gets the recent backlog via REST.
        self.last_packet_seq = capture_engine.latest_seq
        self.last_alert_seq = anomaly_detector.latest_seq()
        self.last_snapshot_ts = 0.0


async def _receive_loop(ws: WebSocket, state: _ClientState) -> None:
    """Apply config messages as they arrive."""
    while True:
        raw = await ws.receive_text()
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        if "packet_limit" in msg:
            try:
                state.packet_limit = max(1, min(int(msg["packet_limit"]), 500))
            except (TypeError, ValueError):
                pass
        if "packets" in msg:
            state.want_packets = bool(msg["packets"])
            state.last_packet_seq = capture_engine.latest_seq


def _build_payload(state: _ClientState) -> dict:
    packets = []
    if state.want_packets:
        new = capture_engine.get_packets_since(state.last_packet_seq, limit=state.packet_limit)
        if new:
            state.last_packet_seq = new[-1].seq
        # If more arrived than we can send, skip ahead instead of lagging.
        state.last_packet_seq = max(state.last_packet_seq, capture_engine.latest_seq)
        packets = [p.to_dict() for p in reversed(new)]   # newest first

    stats = None
    snap = stats_engine.latest_snapshot()
    if snap is not None and snap.timestamp != state.last_snapshot_ts:
        state.last_snapshot_ts = snap.timestamp
        stats = snap.to_dict()

    alerts = anomaly_detector.get_alerts_since(state.last_alert_seq)
    if alerts:
        state.last_alert_seq = alerts[-1].seq

    return {
        "type": "live_update",
        "timestamp": time.time(),
        "packets": packets,
        "stats": stats,
        "new_alerts": [a.to_dict() for a in alerts],
        "capture": capture_engine.get_status(),
        "pipeline": capture_engine.get_metrics()["current"],
        "detection_mode": anomaly_detector.mode,
    }


@router.websocket("/ws/live")
async def live_feed(ws: WebSocket):
    """Real-time packet, stats, and alert feed over WebSocket."""
    await ws.accept()
    state = _ClientState()
    receiver = asyncio.create_task(_receive_loop(ws, state))
    logger.info("WS client connected.")
    try:
        while not receiver.done():
            await ws.send_json(_build_payload(state))
            await asyncio.sleep(PUSH_INTERVAL)
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception as exc:
        logger.debug("WS error: %s", exc)
    finally:
        receiver.cancel()
        logger.info("WS client disconnected.")
