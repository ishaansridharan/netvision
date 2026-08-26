"""
NetVision — Port Scan Detector (detection/port_scan.py)

Detection logic
───────────────
Track distinct destination ports contacted by each source IP within a
configurable sliding time window.  If a single source touches more than
`port_scan_threshold` distinct ports within `port_scan_window_s` seconds,
generate a PORT_SCAN alert.

Why this catches port scans
────────────────────────────
A normal client connects to a small number of ports (443, 80, 53, …).
A port scanner rapidly connects to many different destination ports on
one or more targets.  The ratio of distinct ports to time is the signal.

Alert cooldown
──────────────
After an alert fires for a source IP, that IP is put in a cooldown
period (equal to the window size) to avoid alert storms.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Optional

from backend.config import settings
from backend.detection.models import Alert
from backend.parser.packet_parser import PacketRecord


class PortScanDetector:
    """
    Sliding-window port scan detector.

    State per source IP:
        deque of (timestamp, dst_ip, dst_port) tuples within the window.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # src_ip → deque[(timestamp, dst_ip, dst_port)]
        self._activity: dict[str, deque] = defaultdict(
            lambda: deque()
        )
        # src_ip → last alert timestamp (for cooldown)
        self._last_alert: dict[str, float] = {}

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        """
        Inspect *pkt* for port scan activity.
        Returns an Alert if a scan is detected, else None.
        """
        # Only care about TCP/UDP connection attempts
        if pkt.protocol not in ("TCP", "UDP"):
            return None
        if not pkt.src_ip or not pkt.dst_ip or pkt.dst_port is None:
            return None

        now = pkt.timestamp
        window = settings.port_scan_window_s
        threshold = settings.port_scan_threshold

        with self._lock:
            src = pkt.src_ip

            # Cooldown check
            last = self._last_alert.get(src, 0)
            if now - last < window:
                return None

            buf = self._activity[src]

            # Prune entries outside the sliding window
            cutoff = now - window
            while buf and buf[0][0] < cutoff:
                buf.popleft()

            buf.append((now, pkt.dst_ip, pkt.dst_port))

            # Count distinct (dst_ip, dst_port) pairs
            distinct_ports = len({(dst_ip, dport) for _, dst_ip, dport in buf})

            if distinct_ports >= threshold:
                # Determine the primary scan target (most-contacted dst_ip)
                dst_count: dict[str, int] = defaultdict(int)
                for _, dst, _ in buf:
                    dst_count[dst] += 1
                top_target = max(dst_count, key=lambda k: dst_count[k])

                self._last_alert[src] = now
                self._activity[src].clear()  # Reset after alert

                return Alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    source_ip=src,
                    target_ip=top_target,
                    description=(
                        f"Possible port scan: {src} contacted {distinct_ports} "
                        f"distinct ports within {window:.0f}s."
                    ),
                    evidence={
                        "distinct_ports_contacted": distinct_ports,
                        "window_seconds": window,
                        "threshold": threshold,
                        "primary_target": top_target,
                    },
                )

        return None
