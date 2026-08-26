"""
NetVision — Traffic Spike Detector (detection/traffic_spike.py)

Detection logic
───────────────
We maintain an exponential moving average (EMA) of bytes/sec as a
rolling baseline representing "normal" traffic for this network.

On each update, if the current measurement exceeds:
    baseline * spike_multiplier

and the baseline is large enough to be meaningful (> min_baseline),
we generate a TRAFFIC_SPIKE alert.

EMA formula
───────────
    new_baseline = α * current_rate + (1 - α) * old_baseline

Where α (alpha) controls how quickly the baseline adapts:
    • Small α (0.05) → slow adaptation, stable baseline
    • Large α (0.5)  → fast adaptation, baseline tracks traffic closely

We use α = 0.05 by default so that a spike cannot quickly raise the
baseline and hide itself.

Alert cooldown
──────────────
Minimum 30 seconds between consecutive spike alerts to avoid flooding.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from backend.config import settings
from backend.detection.models import Alert
from backend.parser.packet_parser import PacketRecord


class TrafficSpikeDetector:
    """
    EMA-based traffic spike detector.

    Updated once per second (or whenever the stats engine calls update()).
    Can also be driven directly from packets via process(), but the
    bandwidth measurement is coarser in that mode.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._baseline_bps: float = 0.0
        self._last_alert_time: float = 0.0
        self._cooldown_s: float = 30.0

        # For packet-driven bandwidth estimation
        self._window_start: float = time.time()
        self._window_bytes: int = 0

    def update_from_stats(
        self, current_bps: float, top_source_ip: Optional[str] = None
    ) -> Optional[Alert]:
        """
        Called by the stats engine each snapshot with the current bandwidth.
        Returns an Alert if a spike is detected, else None.
        """
        alpha = settings.traffic_spike_ema_alpha
        multiplier = settings.traffic_spike_multiplier
        min_baseline = settings.traffic_spike_min_baseline

        now = time.time()

        with self._lock:
            # Update EMA baseline
            if self._baseline_bps == 0.0:
                self._baseline_bps = current_bps
            else:
                self._baseline_bps = (
                    alpha * current_bps + (1 - alpha) * self._baseline_bps
                )

            baseline = self._baseline_bps

            # Don't alert until baseline is meaningful
            if baseline < min_baseline:
                return None

            # Check for spike
            if current_bps < baseline * multiplier:
                return None

            # Cooldown check
            if now - self._last_alert_time < self._cooldown_s:
                return None

            self._last_alert_time = now

        current_mbps = current_bps / 1_000_000
        baseline_mbps = baseline / 1_000_000

        return Alert(
            alert_type="TRAFFIC_SPIKE",
            severity="MEDIUM",
            source_ip=top_source_ip,
            target_ip=None,
            description=(
                f"Unusual traffic spike detected: "
                f"{current_mbps:.1f} Mbps (baseline: {baseline_mbps:.1f} Mbps, "
                f"{multiplier:.0f}× threshold)."
            ),
            evidence={
                "current_bps": round(current_bps),
                "baseline_bps": round(baseline),
                "multiplier": multiplier,
                "current_mbps": round(current_mbps, 2),
                "baseline_mbps": round(baseline_mbps, 2),
                "top_source": top_source_ip,
            },
        )

    def get_baseline_mbps(self) -> float:
        with self._lock:
            return self._baseline_bps / 1_000_000
