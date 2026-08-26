"""
GET /stats/current  — real-time network statistics snapshot
GET /stats/history  — time-series history for charting
GET /stats/health   — network health score + component breakdown
GET /stats/arp      — current ARP table (IP→MAC)
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from backend.api.state import stats_engine, anomaly_detector

router = APIRouter(tags=["stats"])


@router.get("/stats/current")
def get_current_stats():
    """
    Return the latest network statistics snapshot.

    This is the primary feed for the Dashboard view:
      • bandwidth (download/upload Mbps)
      • packets/sec
      • protocol distribution
      • top talkers / top destinations
      • latency, jitter, packet loss
      • active connections
      • health score
    """
    snap = stats_engine.latest_snapshot()
    if snap is None:
        return {
            "message": "No data yet — start capture first.",
            "snapshot": None,
        }
    return {"snapshot": snap.to_dict()}


@router.get("/stats/history")
def get_stats_history(
    limit: int = Query(300, ge=1, le=3600, description="Number of 1-second snapshots to return"),
):
    """
    Return time-series stats history for charting (bandwidth over time, etc.).
    Each entry is a snapshot dict.  Ordered oldest → newest.
    """
    history = stats_engine.history(limit=limit)
    return {
        "count": len(history),
        "snapshots": history,
    }


@router.get("/stats/health")
def get_health():
    """Return the network health score with component details."""
    snap = stats_engine.latest_snapshot()
    if snap is None:
        return {"health_score": None, "message": "No data yet."}

    d = snap.to_dict()
    return {
        "health_score": d["health_score"],
        "components": {
            "latency_ms": d["latency_ms"],
            "packet_loss_pct": d["packet_loss_pct"],
            "jitter_ms": d["jitter_ms"],
            "download_mbps": d["download_mbps"],
            "upload_mbps": d["upload_mbps"],
            "active_connections": d["active_connections"],
            "active_alerts": anomaly_detector.get_active_alert_count(),
        },
    }


@router.get("/stats/arp")
def get_arp_table():
    """Return the current observed IP→MAC ARP table."""
    return {"arp_table": anomaly_detector.get_arp_table()}
