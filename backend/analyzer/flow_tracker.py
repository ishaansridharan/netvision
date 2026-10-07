"""
NetVision — Flow Tracker (analyzer/flow_tracker.py)

Groups individual packets into bidirectional network flows (connections).

What is a flow?
───────────────
A flow is identified by a 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, transport)

Because traffic is bidirectional, the lookup key is normalised so that
(A→B) and (B→A) map to the same flow.  The *record* however remembers who
initiated the connection: src_* is always the initiator (the side that sent
the first SYN, or the first packet for UDP/ICMP).  "Forward" therefore
means initiator → responder.

TCP state machine
─────────────────
    SYN_SENT ──SYN-ACK──▶ SYN_RECEIVED ──ACK──▶ ESTABLISHED ──FIN──▶ FIN_WAIT ──FIN──▶ CLOSED
        │                      │                     │
        └────────RST───────────┴─────────RST─────────┴──────────▶ RESET

  • SYN_SENT / SYN_RECEIVED are "half-open": the three-way handshake has
    not completed.  The SYN-flood detector reads this directly.
  • A flow first seen mid-stream (capture started after the handshake) is
    marked ESTABLISHED with `midstream=True`.
  • UDP / ICMP flows are simply ACTIVE.

Handshake RTT
─────────────
SYN→SYN-ACK plus SYN-ACK→ACK equals one round trip no matter where the
capture point sits (client side: the first term is the RTT; server side:
the second is), so it gives a vantage-independent latency sample.

Retransmissions
───────────────
For each direction we remember the highest sequence number covered by a
data segment.  A data segment that ends at or before that point carries
bytes we've already seen — a retransmission, which is the packet-loss
signal used by the stats engine.

Expiry (driven by tick(now), not a wall-clock thread)
─────────────────────────────────────────────────────
  • half-open flows: `flow_half_open_timeout_s`
  • CLOSED / RESET flows: `flow_closed_linger_s`
  • everything else: `flow_idle_timeout_s`
  • the table is capped at `flow_max_active`; least-recently-seen go first.
Using packet time keeps pcap replay deterministic.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from backend.config import Settings, settings as default_settings
from backend.parser.packet_parser import ACK, FIN, RST, SYN, PacketRecord

logger = logging.getLogger(__name__)

HALF_OPEN_STATES = ("SYN_SENT", "SYN_RECEIVED")
TERMINAL_STATES = ("CLOSED", "RESET")

_SEQ_MOD = 1 << 32
_SEQ_HALF = 1 << 31


# ──────────────────────────────────────────────────────────────────────────
# Flow data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """
    Represents a single bidirectional network flow / connection.

    Direction convention
    ────────────────────
    "forward"  = initiator (src_*) → responder (dst_*)
    "backward" = responder → initiator
    """

    flow_id: str          # Canonical, direction-independent key
    src_ip: str           # Initiator
    dst_ip: str           # Responder
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str         # Display protocol (e.g. "DNS")
    transport: str        # "TCP" | "UDP" | "ICMP" | "OTHER"

    start_time: float = 0.0
    last_seen: float = 0.0

    # Packet and byte accounting
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # TCP state
    tcp_state: str = "ACTIVE"
    midstream: bool = False
    handshake_completed: bool = False
    syn_time: Optional[float] = None
    synack_time: Optional[float] = None
    handshake_rtt_ms: Optional[float] = None
    fin_fwd: bool = False
    fin_bwd: bool = False

    # Loss accounting
    data_segments: int = 0
    retransmissions: int = 0
    _max_seq_end: list = field(default_factory=lambda: [None, None], repr=False)

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
    def is_half_open(self) -> bool:
        return self.tcp_state in HALF_OPEN_STATES

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "transport": self.transport,
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
            "midstream": self.midstream,
            "handshake_completed": self.handshake_completed,
            "handshake_rtt_ms": (
                round(self.handshake_rtt_ms, 2)
                if self.handshake_rtt_ms is not None else None
            ),
            "retransmissions": self.retransmissions,
        }


@dataclass
class FlowEvent:
    """What happened to a flow because of one packet."""
    flow: FlowRecord
    forward: bool                         # packet travelled initiator → responder
    is_new: bool = False
    prev_state: Optional[str] = None      # set when tcp_state changed
    retransmission: bool = False
    is_data: bool = False                 # TCP segment carrying payload
    rtt_sample_ms: Optional[float] = None  # set when the handshake completed
    # A new connection attempt started: a new UDP flow, or a pure SYN that
    # opened a TCP flow (including one re-using a closed flow's ports).
    connection_attempt: bool = False

    @property
    def state_changed(self) -> bool:
        return self.prev_state is not None


# ──────────────────────────────────────────────────────────────────────────
# Flow key generation
# ──────────────────────────────────────────────────────────────────────────

def _make_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    transport: str,
) -> str:
    """
    Produce a canonical, direction-independent flow key string.

    We sort (ip, port) endpoint pairs so that A→B and B→A share the same
    key.  Ports default to 0 for portless protocols so the sort never has
    to compare None with int.
    """
    a = (src_ip, src_port or 0)
    b = (dst_ip, dst_port or 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{transport}:{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}"


# ──────────────────────────────────────────────────────────────────────────
# Flow Tracker
# ──────────────────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Maintains a table of active flows and a ring of recently-completed flows.

    process() and tick() are called from the single analysis worker; the
    lock protects reads from API threads.
    """

    def __init__(self, cfg: Settings = default_settings) -> None:
        self._cfg = cfg
        # OrderedDict in least-recently-seen order: move_to_end() on every
        # packet means expiry only has to scan from the front.
        self._active: OrderedDict[str, FlowRecord] = OrderedDict()
        self._completed: deque[FlowRecord] = deque(maxlen=cfg.flow_max_completed)
        self._lock = threading.Lock()
        self._close_callbacks: list[Callable[[FlowRecord], None]] = []

        self.total_flows_seen = 0

    def add_close_callback(self, cb: Callable[[FlowRecord], None]) -> None:
        """Register a function called whenever a flow leaves the active table."""
        self._close_callbacks.append(cb)

    # ------------------------------------------------------------------ #
    # Public: packet ingestion
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord) -> Optional[FlowEvent]:
        """
        Update flow state for *pkt*.  Returns a FlowEvent describing what
        happened, or None if the packet cannot be assigned to a flow
        (e.g. ARP, or no IP addresses).
        """
        if pkt.protocol == "ARP" or not pkt.src_ip or not pkt.dst_ip:
            return None

        transport = pkt.transport or "OTHER"
        sport, dport = pkt.src_port, pkt.dst_port
        if transport == "ICMP" and pkt.icmp_id is not None:
            # Echo id ties request and reply into one "ping session" flow.
            sport = dport = pkt.icmp_id

        key = _make_flow_key(pkt.src_ip, pkt.dst_ip, sport, dport, transport)
        evicted: list[FlowRecord] = []

        with self._lock:
            flow = self._active.get(key)
            is_new = flow is None
            if is_new:
                flow = self._new_flow(key, pkt, transport, sport, dport)
                self._active[key] = flow
                self.total_flows_seen += 1
                if len(self._active) > self._cfg.flow_max_active:
                    _, oldest = self._active.popitem(last=False)
                    self._completed.append(oldest)
                    evicted.append(oldest)
            else:
                self._active.move_to_end(key)

            forward = (pkt.src_ip == flow.src_ip and sport == flow.src_port)
            event = FlowEvent(flow=flow, forward=forward, is_new=is_new)

            # Byte and packet accounting
            flow.last_seen = max(flow.last_seen, pkt.timestamp)
            if forward:
                flow.fwd_packets += 1
                flow.fwd_bytes += pkt.size
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += pkt.size

            if transport == "TCP" and pkt.tcp_flags_raw is not None:
                self._advance_tcp_state(flow, pkt, event, is_new)
                self._track_retransmission(flow, pkt, event)
            elif is_new and transport == "UDP":
                event.connection_attempt = True

        for f in evicted:
            self._notify_closed(f)
        return event

    def _new_flow(
        self, key: str, pkt: PacketRecord, transport: str,
        sport: Optional[int], dport: Optional[int],
    ) -> FlowRecord:
        # If the first packet we see is a SYN-ACK, we missed the SYN: the
        # *destination* of this packet is the real initiator.
        if pkt.is_syn_ack:
            return FlowRecord(
                flow_id=key, src_ip=pkt.dst_ip, dst_ip=pkt.src_ip,
                src_port=dport, dst_port=sport,
                protocol=pkt.protocol, transport=transport,
                start_time=pkt.timestamp, last_seen=pkt.timestamp,
            )
        return FlowRecord(
            flow_id=key, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
            src_port=sport, dst_port=dport,
            protocol=pkt.protocol, transport=transport,
            start_time=pkt.timestamp, last_seen=pkt.timestamp,
        )

    # ------------------------------------------------------------------ #
    # TCP state machine
    # ------------------------------------------------------------------ #

    def _advance_tcp_state(
        self, flow: FlowRecord, pkt: PacketRecord, event: FlowEvent, is_new: bool
    ) -> None:
        flags = pkt.tcp_flags_raw or 0
        syn, ack = bool(flags & SYN), bool(flags & ACK)
        rst, fin = bool(flags & RST), bool(flags & FIN)
        now = pkt.timestamp
        old = flow.tcp_state

        if is_new:
            if syn and not ack:
                new = "SYN_SENT"
                flow.syn_time = now
                event.connection_attempt = True
            elif syn and ack:
                new = "SYN_RECEIVED"
                flow.synack_time = now
            elif rst:
                new = "RESET"
            else:
                new = "ESTABLISHED"
                flow.midstream = True
            flow.tcp_state = new
            event.prev_state = "NEW"
            return

        new = old
        if syn and not ack and event.forward and old in TERMINAL_STATES:
            # Same 5-tuple re-used for a fresh connection attempt.
            new = "SYN_SENT"
            flow.syn_time = now
            flow.synack_time = None
            flow.handshake_completed = False
            flow.fin_fwd = flow.fin_bwd = False
            event.connection_attempt = True
        elif rst:
            if old not in TERMINAL_STATES:
                new = "RESET"
        elif old == "SYN_SENT":
            if syn and ack and not event.forward:
                new = "SYN_RECEIVED"
                flow.synack_time = now
        elif old == "SYN_RECEIVED":
            if ack and not syn and event.forward:
                new = "ESTABLISHED"
                flow.handshake_completed = True
                if flow.syn_time is not None and flow.synack_time is not None:
                    rtt = (now - flow.syn_time) * 1000
                    if 0 <= rtt < 10_000:
                        flow.handshake_rtt_ms = rtt
                        event.rtt_sample_ms = rtt
        elif old == "ESTABLISHED":
            if fin:
                new = "FIN_WAIT"
        if fin and new in ("FIN_WAIT", "ESTABLISHED"):
            if event.forward:
                flow.fin_fwd = True
            else:
                flow.fin_bwd = True
            if flow.fin_fwd and flow.fin_bwd:
                new = "CLOSED"

        if new != old:
            flow.tcp_state = new
            event.prev_state = old

    def _track_retransmission(
        self, flow: FlowRecord, pkt: PacketRecord, event: FlowEvent
    ) -> None:
        if pkt.payload_len <= 0 or pkt.tcp_seq is None:
            return
        event.is_data = True
        flow.data_segments += 1
        idx = 0 if event.forward else 1
        seq_end = (pkt.tcp_seq + pkt.payload_len) % _SEQ_MOD
        prev = flow._max_seq_end[idx]
        if prev is None:
            flow._max_seq_end[idx] = seq_end
            return
        # Serial-number arithmetic (RFC 1982) handles 32-bit wrap-around.
        diff = (seq_end - prev) % _SEQ_MOD
        if diff == 0 or diff > _SEQ_HALF:
            flow.retransmissions += 1
            event.retransmission = True
        else:
            flow._max_seq_end[idx] = seq_end

    # ------------------------------------------------------------------ #
    # Expiry
    # ------------------------------------------------------------------ #

    def tick(self, now: float) -> int:
        """Evict expired flows.  Returns the number evicted."""
        cfg = self._cfg
        min_timeout = min(
            cfg.flow_closed_linger_s, cfg.flow_half_open_timeout_s, cfg.flow_idle_timeout_s
        )
        evicted: list[FlowRecord] = []

        with self._lock:
            # Front of the OrderedDict = least recently seen.  Once we reach
            # a flow younger than the shortest timeout, nothing behind it
            # can be expired either.
            for key in list(self._active.keys()):
                flow = self._active[key]
                idle = now - flow.last_seen
                if idle < min_timeout:
                    break
                if flow.tcp_state in TERMINAL_STATES:
                    timeout = cfg.flow_closed_linger_s
                elif flow.tcp_state in HALF_OPEN_STATES:
                    timeout = cfg.flow_half_open_timeout_s
                else:
                    timeout = cfg.flow_idle_timeout_s
                if idle > timeout:
                    del self._active[key]
                    self._completed.append(flow)
                    evicted.append(flow)

        for flow in evicted:
            self._notify_closed(flow)
        if evicted:
            logger.debug("Flow expiry: evicted %d flows.", len(evicted))
        return len(evicted)

    def _notify_closed(self, flow: FlowRecord) -> None:
        for cb in self._close_callbacks:
            try:
                cb(flow)
            except Exception as exc:
                logger.debug("Flow close callback error: %s", exc)

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

    def get_flow(self, flow_id: str) -> Optional[FlowRecord]:
        with self._lock:
            flow = self._active.get(flow_id)
            if flow:
                return flow
            for f in self._completed:
                if f.flow_id == flow_id:
                    return f
        return None

    def get_stats(self) -> dict:
        with self._lock:
            states: dict[str, int] = {}
            half_open = 0
            for f in self._active.values():
                if f.transport == "TCP":
                    states[f.tcp_state] = states.get(f.tcp_state, 0) + 1
                    if f.tcp_state in HALF_OPEN_STATES:
                        half_open += 1
            return {
                "active_flows": len(self._active),
                "completed_flows": len(self._completed),
                "half_open_flows": half_open,
                "tcp_states": states,
                "total_flows_seen": self.total_flows_seen,
            }
