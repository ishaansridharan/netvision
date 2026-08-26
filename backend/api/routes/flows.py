"""
GET /flows          — active and recently completed flows
GET /flows/stats    — flow count summary
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from backend.api.state import flow_tracker

router = APIRouter(tags=["flows"])


@router.get("/flows")
def get_flows(
    limit: int = Query(200, ge=1, le=2000),
    protocol: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    active_only: bool = Query(False, description="Return only currently active flows"),
):
    """Return network flows sorted newest-last-seen first."""
    if active_only:
        flows = flow_tracker.get_active_flows()
    else:
        flows = flow_tracker.get_all_flows(limit=limit * 2)  # Over-fetch then filter

    if protocol:
        flows = [f for f in flows if f.protocol == protocol.upper()]
    if src_ip:
        flows = [f for f in flows if f.src_ip == src_ip or f.dst_ip == src_ip]
    if dst_ip:
        flows = [f for f in flows if f.dst_ip == dst_ip or f.src_ip == dst_ip]

    flows = sorted(flows, key=lambda f: f.last_seen, reverse=True)[:limit]

    return {
        "count": len(flows),
        "flows": [f.to_dict() for f in flows],
    }


@router.get("/flows/stats")
def get_flow_stats():
    """Return summary counts of active and completed flows."""
    return flow_tracker.get_stats()
