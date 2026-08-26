"""
NetVision — Flow Tracker (analyzer/flow_tracker.py)

Groups individual packets into bidirectional network flows (connections).

What is a flow?
───────────────
A flow is identified by a 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)

Because traffic is bidirectional, we normalise the tuple so that:
    (A→B) and (B→A) map to the same flow key.

This means a single flow captures both the request and the response
in a TCP or UDP exchange — which is exactly what the dashboard needs.

Flow state machine (TCP)
────────────────────────
    INIT → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED
                           ↑
                     (SYN-ACK seen)

For UDP and other protocols the state is simply ACTIVE → EXPIRED.

Flow expiry
───────────
A GC thread periodically evicts flows that have been idle longer than
`flow_idle_timeout_s` (default 60 s). Evicted flows are moved to a
`completed_flows` deque so the API can still serve historical data.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from backend.config import settings
from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────
# Flow data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """
    Represents a single bidirectional network flow / connection.

    Direction convention
    ────────────────────
    "forward"  = packets travelling from flow_key[0] → flow_key[1]
    "backward" = packets travelling from flow_key[1] → flow_key[0]
    """

    flow_id: str          # Canonical string key
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str

    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Packet and byte accounting
    fwd_packets: int = 0       # src→dst
    bwd_packets: int = 0       # dst→src
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # TCP state
    tcp_state: str = "INIT"    # INIT | SYN_SENT | ESTABLISHED | FIN_WAIT | CLOSED

    # Convenience properties
    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > settings.flow_idle_timeout_s

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 3),
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "total_packets": self.total_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "total_bytes": self.total_bytes,
            "tcp_state": self.tcp_state,
        }


# ──────────────────────────────────────────────────────────────────────────
# Flow key generation
# ──────────────────────────────────────────────────────────────────────────

def _make_flow_key(
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> str:
    """
    Produce a canonical, direction-independent flow key string.

    We sort (src, sport) and (dst, dport) so that A→B and B→A share
    the same key.  Port is included in the sort key so that symmetrical
    port numbers (e.g. both side 80) still resolve deterministically.
    """
    a = (src_ip or "", src_port or 0)
    b = (dst_ip or "", dst_port or 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{protocol}:{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}"


# ──────────────────────────────────────────────────────────────────────────
# Flow Tracker
# ──────────────────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Maintains a table of active flows and a ring of recently-completed flows.

    Thread safety: all public methods acquire self._lock.
    The GC thread also holds the lock during eviction.
    """

    # Maximum completed flows kept in memory
    _MAX_COMPLETED = 5_000

    def __init__(self) -> None:
        self._active: dict[str, FlowRecord] = {}
        self._completed: deque[FlowRecord] = deque(maxlen=self._MAX_COMPLETED)
        self._lock = threading.Lock()

        self._gc_thread = threading.Thread(
            target=self._gc_loop,
            name="netvision-flow-gc",
            daemon=True,
        )
        self._gc_thread.start()

    # ------------------------------------------------------------------ #
    # Public: packet ingestion
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord) -> FlowRecord | None:
        """
        Update flow state for *pkt*.  Returns the affected FlowRecord,
        or None if the packet cannot be assigned to a flow (e.g. bare ARP).
        """
        # ARP packets don't form IP flows
        if pkt.protocol == "ARP":
            return None

        # Must have at least src/dst IP to form a flow
        if not pkt.src_ip or not pkt.dst_ip:
            return None

        key = _make_flow_key(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol
        )
        forward = (pkt.src_ip, pkt.src_port) <= (pkt.dst_ip, pkt.dst_port or 0)

        with self._lock:
            if key not in self._active:
                # New flow — initialise
                flow = FlowRecord(
                    flow_id=key,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    last_seen=pkt.timestamp,
                )
                self._active[key] = flow
            else:
                flow = self._active[key]

            # Byte and packet accounting
            flow.last_seen = pkt.timestamp
            if forward:
                flow.fwd_packets += 1
                flow.fwd_bytes += pkt.size
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += pkt.size

            # TCP state machine
            if pkt.protocol == "TCP" and pkt.tcp_flags:
                self._advance_tcp_state(flow, pkt.tcp_flags)

        return flow

    # ------------------------------------------------------------------ #
    # Public: accessors
    # ------------------------------------------------------------------ #

    def get_active_flows(self) -> list[FlowRecord]:
        with self._lock:
            return list(self._active.values())

    def get_completed_flows(self, limit: int = 500) -> list[FlowRecord]:
        with self._lock:
            flows = list(self._completed)
        return flows[-limit:]

    def get_all_flows(self, limit: int = 500) -> list[FlowRecord]:
        with self._lock:
            active = list(self._active.values())
            completed = list(self._completed)
        combined = completed + active
        combined.sort(key=lambda f: f.last_seen, reverse=True)
        return combined[:limit]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "active_flows": len(self._active),
                "completed_flows": len(self._completed),
            }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _advance_tcp_state(self, flow: FlowRecord, flags: str) -> None:
        """
        Minimal TCP state machine driven by flag strings.
        We only track states relevant to anomaly detection.
        """
        state = flow.tcp_state
        if state == "INIT":
            if "SYN" in flags and "ACK" not in flags:
                flow.tcp_state = "SYN_SENT"
        elif state == "SYN_SENT":
            if "SYN" in flags and "ACK" in flags:
                flow.tcp_state = "ESTABLISHED"
            elif "RST" in flags:
                flow.tcp_state = "CLOSED"
        elif state == "ESTABLISHED":
            if "FIN" in flags:
                flow.tcp_state = "FIN_WAIT"
            elif "RST" in flags:
                flow.tcp_state = "CLOSED"
        elif state == "FIN_WAIT":
            if "ACK" in flags:
                flow.tcp_state = "CLOSED"

    def _gc_loop(self) -> None:
        """Periodically evict idle flows."""
        while True:
            time.sleep(settings.flow_gc_interval_s)
            self._evict_idle()

    def _evict_idle(self) -> None:
        now = time.time()
        with self._lock:
            expired_keys = [
                k for k, f in self._active.items()
                if (now - f.last_seen) > settings.flow_idle_timeout_s
            ]
            for key in expired_keys:
                flow = self._active.pop(key)
                flow.tcp_state = "CLOSED" if flow.tcp_state not in ("CLOSED",) else flow.tcp_state
                self._completed.append(flow)

        if expired_keys:
            logger.debug("Flow GC: evicted %d idle flows.", len(expired_keys))
