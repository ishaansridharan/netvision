"""
GET /flows            — active and recently completed flows
GET /flows/stats      — flow counts, half-open count, TCP state breakdown
GET /flows/{flow_id}  — single flow
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from backend.api.state import flow_tracker

router = APIRouter(tags=["flows"])


@router.get("/flows")
def get_flows(
    limit: int = Query(200, ge=1, le=2000),
    protocol: Optional[str] = Query(None),
    ip: Optional[str] = Query(None, description="Match either endpoint"),
    state: Optional[str] = Query(None, description="TCP state, e.g. ESTABLISHED, SYN_SENT"),
    active_only: bool = Query(False, description="Return only currently active flows"),
    sort: str = Query("recent", pattern="^(recent|bytes|packets)$"),
):
    """Return network flows (newest-last-seen first by default)."""
    flows = flow_tracker.get_active_flows() if active_only else flow_tracker.get_all_flows(limit=5_000)

    if protocol:
        p = protocol.upper()
        flows = [f for f in flows if f.protocol == p or f.transport == p]
    if ip:
        flows = [f for f in flows if ip in (f.src_ip, f.dst_ip)]
    if state:
        flows = [f for f in flows if f.tcp_state == state.upper()]

    key = {
        "recent": lambda f: f.last_seen,
        "bytes": lambda f: f.total_bytes,
        "packets": lambda f: f.total_packets,
    }[sort]
    flows = sorted(flows, key=key, reverse=True)[:limit]
    return {"count": len(flows), "flows": [f.to_dict() for f in flows]}


@router.get("/flows/stats")
def get_flow_stats():
    """Active / completed / half-open counts and the TCP state breakdown."""
    return flow_tracker.get_stats()


@router.get("/flows/{flow_id:path}")
def get_flow(flow_id: str):
    flow = flow_tracker.get_flow(flow_id)
    if flow is None:
        raise HTTPException(404, f"Flow '{flow_id}' not found.")
    return flow.to_dict()
