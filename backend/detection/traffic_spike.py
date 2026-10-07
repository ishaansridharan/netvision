"""
NetVision — Traffic Spike Detector (detection/traffic_spike.py)

Signal
──────
Total throughput of the last complete second (bytes/sec), taken from the
stats snapshot on every tick.  The 1-second value is used rather than the
10-second rolling average so a spike is not smoothed away before it is
detected.

Static mode
───────────
    throughput ≥ traffic_spike_static_bps            (default 10 Mbit/s)

A fixed number is either too low for a busy network (constant alerts) or
too high for a quiet one (spikes missed) — the problem the report sets
out to fix.

Adaptive mode
─────────────
EWMA baseline of per-second throughput (see detection/baseline.py):

    throughput ≥ max(μ + k·σ,  multiplier·μ,  min_bps)

  • μ + k·σ        — statistically unusual for this network
  • multiplier·μ   — and a material jump, not a wobble on a flat baseline
  • min_bps        — and large enough in absolute terms to matter

While the baseline is warming up the detector falls back to the static
threshold, and says so in the explanation.

Both modes require `traffic_spike_min_duration_s` consecutive anomalous
seconds, which filters single-second bursts (a page load, a TCP slow-start
overshoot), and respect a cooldown between alerts.
"""

from __future__ import annotations

from typing import Optional

from backend.config import Settings, settings as default_settings
from backend.detection.baseline import EWMABaseline
from backend.detection.models import Alert, explain


class TrafficSpikeDetector:
    """EWMA + z-score traffic spike detector (static or adaptive)."""

    def __init__(self, cfg: Settings = default_settings, mode: str = "adaptive") -> None:
        self._cfg = cfg
        self.mode = mode
        self._baseline = EWMABaseline(
            alpha=cfg.baseline_alpha,
            k=cfg.baseline_z_threshold,
            warmup=cfg.baseline_warmup_samples,
            floor=cfg.traffic_spike_min_bps,
            min_std=10_000.0,   # 10 kB/s — σ below this is measurement noise
            cold_clip=cfg.traffic_spike_static_bps,
        )
        self._consecutive = 0
        self._spike_started: Optional[float] = None
        self._last_alert_time = float("-inf")

    def pause(self) -> None:
        """Not observing: forget any partial spike; the baseline is untouched."""
        self._consecutive = 0
        self._spike_started = None

    def check(
        self,
        now: float,
        current_bps: float,
        top_talkers: Optional[list[dict]] = None,
    ) -> Optional[Alert]:
        """Called once per tick with the last full second's throughput."""
        cfg = self._cfg
        b = self._baseline

        # Decide against the baseline *before* learning from this sample.
        mean, std, ready = b.mean, b.std, b.ready
        z = b.z_score(current_bps) if b.n else None
        if self.mode == "static" or not ready:
            threshold = cfg.traffic_spike_static_bps
            rule = f"throughput ≥ {_rate(threshold)} (fixed)"
            if self.mode == "adaptive":
                rule += f" — baseline warming up ({b.n}/{b.warmup} s)"
        else:
            threshold = max(b.threshold(), cfg.traffic_spike_multiplier * mean,
                            cfg.traffic_spike_min_bps)
            rule = "throughput ≥ max(μ + k·σ, multiplier·μ, min_bps)"

        anomalous = current_bps >= threshold
        b.update(current_bps)

        if anomalous:
            if self._consecutive == 0:
                self._spike_started = now - 1.0   # the sample covers the previous second
            self._consecutive += 1
        else:
            self._consecutive = 0
            self._spike_started = None

        if self._consecutive < cfg.traffic_spike_min_duration_s:
            return None
        if now - self._last_alert_time < cfg.traffic_spike_cooldown_s:
            return None
        self._last_alert_time = now

        top = (top_talkers or [None])[0]
        top_ip = top["ip"] if top else None
        current_mbps = current_bps * 8 / 1e6
        baseline_mbps = mean * 8 / 1e6
        factors = [
            f"Above threshold for {self._consecutive} consecutive seconds.",
        ]
        if top:
            factors.append(
                f"Largest contributor: {top.get('name') or top_ip} "
                f"({top['pct']:.0f}% of traffic in the last "
                f"{cfg.stats_rolling_window_s:.0f}s)."
            )
        if mean > 0:
            factors.append(f"{current_bps / mean:.1f}× the baseline mean.")

        adaptive_decision = self.mode == "adaptive" and ready
        if adaptive_decision:
            summary = (
                f"Throughput jumped to {_rate(current_bps)}; normal for this "
                f"network is {_rate(mean)} ± {_rate(std)}, so anything above "
                f"{_rate(threshold)} is unusual."
            )
        else:
            summary = (
                f"Throughput reached {_rate(current_bps)}, above the fixed "
                f"threshold of {_rate(threshold)}."
            )

        severity = "HIGH" if current_bps >= 3 * threshold else "MEDIUM"
        return Alert(
            timestamp=now,
            alert_type="TRAFFIC_SPIKE",
            severity=severity,
            mode=self.mode,
            source_ip=top_ip,
            target_ip=None,
            description=(
                f"Unusual traffic spike: {_rate(current_bps)} (baseline {_rate(mean)})."
            ),
            evidence={
                "current_bps": round(current_bps),
                "baseline_bps": round(mean),
                "baseline_std_bps": round(std),
                "threshold_bps": round(threshold),
                "current_mbps": round(current_mbps, 3),
                "baseline_mbps": round(baseline_mbps, 3),
                "consecutive_seconds": self._consecutive,
                "spike_started": self._spike_started,
                "top_source": top_ip,
                "top_source_pct": top["pct"] if top else None,
            },
            explanation=explain(
                summary=summary,
                metric="total throughput over the last second",
                observed=current_bps,
                threshold=threshold,
                rule=rule,
                baseline=b.view("network") if adaptive_decision else None,
                z_score=z if adaptive_decision else None,
                factors=factors,
            ),
        )

    def baseline_summary(self) -> dict:
        b = self._baseline
        return {
            "population": b.view("network").to_dict(),
            "current_threshold_bps": round(
                max(b.threshold(), self._cfg.traffic_spike_multiplier * b.mean,
                    self._cfg.traffic_spike_min_bps)
                if b.ready else self._cfg.traffic_spike_static_bps
            ),
        }

    def get_baseline_mbps(self) -> float:
        return self._baseline.mean * 8 / 1e6


def _rate(bytes_per_s: float) -> str:
    """Bytes/s as a human bit rate with a unit chosen by magnitude."""
    bits = bytes_per_s * 8
    if bits >= 1e9:
        return f"{bits / 1e9:.2f} Gbit/s"
    if bits >= 1e6:
        return f"{bits / 1e6:.2f} Mbit/s"
    return f"{bits / 1e3:.1f} kbit/s"
