"""
GET /health             — API liveness and component status
GET /metrics/pipeline   — throughput, processing time and drop rate
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Query

from backend.api.state import anomaly_detector, capture_engine, db_writer, stats_engine

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check():
    """
    Liveness endpoint with component status.  The frontend polls this to
    show a 'Backend Connected' indicator.
    """
    snap = stats_engine.latest_snapshot()
    return {
        "status": "ok",
        "timestamp": time.time(),
        "components": {
            "capture": capture_engine.get_status(),
            "stats": {
                "has_data": snap is not None,
                "last_snapshot": snap.timestamp if snap else None,
            },
            "detection": {
                "mode": anomaly_detector.mode,
                "active_alerts": anomaly_detector.get_active_alert_count(),
            },
            "database": {"written": db_writer.written, "dropped": db_writer.dropped},
        },
    }


@router.get("/metrics/pipeline")
def pipeline_metrics(history: int = Query(60, ge=0, le=300)):
    """
    Real-time processing metrics from the report's evaluation plan:
      • processing throughput (packets/sec analysed, and estimated capacity)
      • per-packet processing time
      • packet drop rate (packets the analysis queue could not accept)
    """
    return {
        **capture_engine.get_metrics(),
        "history": capture_engine.get_metrics_history(history) if history else [],
    }
