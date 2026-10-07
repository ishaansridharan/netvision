"""
GET /packets            — recent packets with filters
GET /packets/{id}       — full detail of a specific packet
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from backend.api.state import capture_engine

router = APIRouter(tags=["packets"])


@router.get("/packets")
def get_packets(
    limit: int = Query(100, ge=1, le=2000),
    protocol: Optional[str] = Query(None, description="Filter by protocol e.g. TCP, UDP, DNS"),
    ip: Optional[str] = Query(None, description="Match either source or destination IP"),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    port: Optional[int] = Query(None, description="Match either source or destination port"),
    src_port: Optional[int] = Query(None),
    dst_port: Optional[int] = Query(None),
    min_size: Optional[int] = Query(None),
    max_size: Optional[int] = Query(None),
    search: Optional[str] = Query(None, description="Case-insensitive match on the summary line"),
    since_seq: Optional[int] = Query(None, description="Only packets newer than this sequence number"),
):
    """
    Return recent captured packets from the in-memory ring buffer.
    All filters are optional and applied server-side.  Newest packets first.
    """
    packets = capture_engine.get_recent_packets()
    packets.reverse()  # Newest first

    if since_seq is not None:
        packets = [p for p in packets if p.seq > since_seq]
    if protocol:
        proto_upper = protocol.upper()
        packets = [p for p in packets if p.protocol == proto_upper or p.transport == proto_upper]
    if ip:
        packets = [p for p in packets if ip in (p.src_ip, p.dst_ip)]
    if src_ip:
        packets = [p for p in packets if p.src_ip == src_ip]
    if dst_ip:
        packets = [p for p in packets if p.dst_ip == dst_ip]
    if port is not None:
        packets = [p for p in packets if port in (p.src_port, p.dst_port)]
    if src_port is not None:
        packets = [p for p in packets if p.src_port == src_port]
    if dst_port is not None:
        packets = [p for p in packets if p.dst_port == dst_port]
    if min_size is not None:
        packets = [p for p in packets if p.size >= min_size]
    if max_size is not None:
        packets = [p for p in packets if p.size <= max_size]
    if search:
        needle = search.lower()
        packets = [p for p in packets if needle in p.raw_summary.lower()]

    packets = packets[:limit]
    return {
        "count": len(packets),
        "latest_seq": capture_engine.latest_seq,
        "packets": [p.to_dict() for p in packets],
    }


@router.get("/packets/{packet_id}")
def get_packet(packet_id: str):
    """Return full details for a single packet by ID."""
    for pkt in capture_engine.get_recent_packets():
        if pkt.id == packet_id:
            return pkt.to_dict()
    raise HTTPException(status_code=404, detail=f"Packet '{packet_id}' not found in ring buffer.")
