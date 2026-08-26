"""
GET /health — API liveness and component status
"""

from __future__ import annotations

import time

from fastapi import APIRouter

from backend.api.state import capture_engine, stats_engine, anomaly_detector

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check():
    """
    Liveness endpoint.  Returns component status for quick diagnostics.
    The frontend can poll this to show a 'Backend Connected' indicator.
    """
    snap = stats_engine.latest_snapshot()
    return {
        "status": "ok",
        "timestamp": time.time(),
        "components": {
            "capture": {
                "running": capture_engine.is_running,
                "interface": capture_engine.interface,
                "total_packets": capture_engine.total_packets,
            },
            "stats": {
                "has_data": snap is not None,
                "last_snapshot": snap.timestamp if snap else None,
            },
            "alerts": {
                "active_count": anomaly_detector.get_active_alert_count(),
            },
        },
    }
