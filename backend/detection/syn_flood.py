"""
NetVision — SYN Flood Detector (detection/syn_flood.py)

Detection logic
───────────────
Normal TCP handshake:
    Client → Server : SYN
    Server → Client : SYN-ACK
    Client → Server : ACK    (connection ESTABLISHED)

SYN flood pattern:
    Attacker → Server : SYN  ×  N
    Server → Attacker : SYN-ACK  ×  N   (server exhausts resources)
    Attacker            never sends ACK   (connections stay half-open)

We track per-destination IP within a sliding time window:
    • syn_count   — total SYN packets seen
    • ack_count   — total ACKs that complete a handshake (SYN-ACK + ACK)

If syn_count exceeds the threshold AND the ratio of incomplete connections
exceeds incomplete_ratio, we fire a SYN_FLOOD alert.

Limitation / honesty
────────────────────
We label this "Possible SYN Flood" because spoofed-source SYNs,
asymmetric routing, or high-traffic servers can produce a similar pattern
without any malicious intent.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Optional

from backend.config import settings
from backend.detection.models import Alert
from backend.parser.packet_parser import PacketRecord


class SynFloodDetector:
    """
    Per-destination sliding-window SYN flood detector.

    We track SYN and completing-ACK counts per destination.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # dst_ip → deque of (timestamp, event_type)
        # event_type: "SYN" | "ACK_COMPLETE"
        self._events: dict[str, deque] = defaultdict(deque)
        # Cooldown: dst_ip → last alert time
        self._last_alert: dict[str, float] = {}

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if pkt.protocol != "TCP" or not pkt.dst_ip:
            return None

        flags = pkt.tcp_flags or ""
        event: Optional[str] = None

        if flags == "SYN":
            event = "SYN"
        elif flags in ("ACK", "SYN-ACK"):
            event = "ACK_COMPLETE"

        if event is None:
            return None

        now = pkt.timestamp
        window = settings.syn_flood_window_s
        threshold = settings.syn_flood_syn_threshold
        ratio_limit = settings.syn_flood_incomplete_ratio
        dst = pkt.dst_ip

        with self._lock:
            # Cooldown check
            last = self._last_alert.get(dst, 0)
            if now - last < window:
                return None

            buf = self._events[dst]

            # Prune old entries
            cutoff = now - window
            while buf and buf[0][0] < cutoff:
                buf.popleft()

            buf.append((now, event))

            # Count events
            syn_count = sum(1 for _, t in buf if t == "SYN")
            ack_count = sum(1 for _, t in buf if t == "ACK_COMPLETE")
            incomplete = syn_count - ack_count

            if syn_count < threshold:
                return None

            incomplete_ratio = incomplete / syn_count if syn_count else 0.0

            if incomplete_ratio >= ratio_limit:
                self._last_alert[dst] = now
                self._events[dst].clear()

                return Alert(
                    alert_type="SYN_FLOOD",
                    severity="HIGH",
                    source_ip=pkt.src_ip,
                    target_ip=dst,
                    description=(
                        f"Possible SYN flood targeting {dst}: "
                        f"{syn_count} SYNs, only {ack_count} completed "
                        f"({incomplete} incomplete = {incomplete_ratio:.0%})."
                    ),
                    evidence={
                        "syn_count": syn_count,
                        "completed_count": ack_count,
                        "incomplete_count": incomplete,
                        "incomplete_ratio": round(incomplete_ratio, 3),
                        "window_seconds": window,
                        "threshold": threshold,
                    },
                )

        return None
