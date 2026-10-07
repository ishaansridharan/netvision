"""
GET /stats/current  — real-time network statistics snapshot
GET /stats/history  — time-series history for charting
GET /stats/health   — network health score + explained components
GET /stats/arp      — current ARP table (IP→MAC) and recent re-bindings
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from backend.api.state import anomaly_detector, stats_engine

router = APIRouter(tags=["stats"])


@router.get("/stats/current")
def get_current_stats():
    """
    Latest network statistics snapshot — the primary feed for the Dashboard:
    bandwidth, packets/sec, protocol distribution, top talkers, latency,
    jitter, loss estimate, connections and the explained health score.
    """
    snap = stats_engine.latest_snapshot()
    if snap is None:
        return {"message": "No data yet.", "snapshot": None}
    return {"snapshot": snap.to_dict()}


@router.get("/stats/history")
def get_stats_history(
    limit: int = Query(300, ge=1, le=3600, description="Number of 1-second snapshots"),
    compact: bool = Query(True, description="Drop bulky per-snapshot fields"),
):
    """Time-series stats history for charting, oldest → newest."""
    history = stats_engine.history(limit=limit)
    if compact:
        keep = (
            "timestamp", "download_bps", "upload_bps", "lan_bps", "total_bps",
            "instant_bps", "packets_per_sec", "latency_ms", "jitter_ms",
            "packet_loss_pct", "active_connections", "half_open_connections",
            "health_score",
        )
        history = [{k: s[k] for k in keep} for s in history]
    return {"count": len(history), "snapshots": history}


@router.get("/stats/health")
def get_health():
    """Health score with a per-component breakdown and plain-language issues."""
    snap = stats_engine.latest_snapshot()
    if snap is None:
        return {"health_score": None, "message": "No data yet."}
    return {
        "health_score": snap.health_score,
        "components": snap.health["components"],
        "issues": snap.health["issues"],
    }


@router.get("/stats/arp")
def get_arp_table():
    """Observed IP→MAC table and mapping changes judged to be re-bindings."""
    return {
        "arp_table": anomaly_detector.get_arp_table(),
        "rebindings": anomaly_detector.get_arp_rebindings(),
    }
