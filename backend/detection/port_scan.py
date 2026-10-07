"""
NetVision — Port Scan Detector (detection/port_scan.py)

Signal: distinct-port fan-out
─────────────────────────────
For each source IP we track the *connection attempts* it initiated within a
sliding window (`port_scan_window_s`): new TCP flows opened with a SYN, and
new UDP flows.  The fan-out is the number of distinct destination ports in
that window.

Working from flow-level connection attempts (instead of raw packets) is
what keeps busy servers quiet: a web server replying to a hundred clients
sends packets to a hundred different client ports, but those packets all
belong to flows the *clients* initiated, so they never count against the
server.

Static mode
───────────
    fan_out ≥ port_scan_threshold                    (default 15)

Adaptive mode
─────────────
    fan_out ≥ max(floor, μ + k·σ)

where μ, σ come from an EWMA baseline of fan-out sampled every second.
Each source is judged against its *own* baseline once that has warmed up,
and against the network-wide (population) baseline before then.  A host
that legitimately talks to many ports (P2P client, monitoring server)
raises its own threshold instead of alerting forever.

Supporting evidence (flow context)
──────────────────────────────────
  • failed ratio — share of attempted TCP connections that were refused
    (RST) or are still unanswered.  Scans hit mostly closed ports, so this
    is high; a legitimate burst of connections mostly succeeds.
  • distinct targets — one target = vertical scan, many = sweep.
High failed ratio raises severity to HIGH.

Alert cooldown
──────────────
After an alert, the source is muted for `port_scan_cooldown_s` to avoid
alert storms while the scan continues.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Optional

from backend.analyzer.flow_tracker import FlowEvent, FlowRecord
from backend.config import Settings, settings as default_settings
from backend.detection.baseline import BaselineTable
from backend.detection.models import Alert, explain
from backend.parser.packet_parser import PacketRecord


class _SourceWindow:
    """Connection attempts by one source within the sliding window."""

    __slots__ = ("attempts", "port_counts", "host_counts")

    def __init__(self) -> None:
        self.attempts: deque[tuple[float, str, int, FlowRecord]] = deque()
        self.port_counts: Counter = Counter()
        self.host_counts: Counter = Counter()

    def add(self, ts: float, dst_ip: str, dst_port: int, flow: FlowRecord) -> None:
        self.attempts.append((ts, dst_ip, dst_port, flow))
        self.port_counts[dst_port] += 1
        self.host_counts[dst_ip] += 1

    def prune(self, cutoff: float) -> None:
        attempts = self.attempts
        while attempts and attempts[0][0] < cutoff:
            _, dst_ip, dst_port, _ = attempts.popleft()
            self.port_counts[dst_port] -= 1
            if self.port_counts[dst_port] <= 0:
                del self.port_counts[dst_port]
            self.host_counts[dst_ip] -= 1
            if self.host_counts[dst_ip] <= 0:
                del self.host_counts[dst_ip]

    @property
    def fan_out(self) -> int:
        return len(self.port_counts)


class PortScanDetector:
    """Flow-aware sliding-window port scan detector (static or adaptive)."""

    def __init__(self, cfg: Settings = default_settings, mode: str = "adaptive") -> None:
        self._cfg = cfg
        self.mode = mode
        self._windows: dict[str, _SourceWindow] = {}
        self._last_alert: dict[str, float] = {}
        self._baselines = BaselineTable(
            alpha=cfg.baseline_alpha,
            k=cfg.baseline_z_threshold,
            warmup=cfg.baseline_warmup_samples,
            floor=float(cfg.port_scan_adaptive_floor),
            min_std=1.0,
            cold_clip=float(cfg.port_scan_threshold),
        )

    # ------------------------------------------------------------------ #
    # Per packet
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord, event: Optional[FlowEvent]) -> Optional[Alert]:
        if event is None or not event.connection_attempt:
            return None
        flow = event.flow
        if flow.dst_port is None:
            return None

        now = pkt.timestamp
        src = flow.src_ip
        win = self._windows.get(src)
        if win is None:
            win = self._windows[src] = _SourceWindow()
        win.prune(now - self._cfg.port_scan_window_s)
        win.add(now, flow.dst_ip, flow.dst_port, flow)

        if now - self._last_alert.get(src, float("-inf")) < self._cfg.port_scan_cooldown_s:
            return None

        fan_out = win.fan_out
        if self.mode == "static":
            threshold = float(self._cfg.port_scan_threshold)
            if fan_out < threshold:
                return None
            return self._alert(now, src, win, fan_out, threshold, None, None)

        baseline, scope = self._baselines.for_key(src)
        threshold = baseline.threshold()
        if fan_out < threshold:
            return None
        return self._alert(
            now, src, win, fan_out, threshold, baseline.view(scope), baseline.z_score(fan_out)
        )

    # ------------------------------------------------------------------ #
    # Per tick — learn baselines, drop idle sources
    # ------------------------------------------------------------------ #

    def tick(self, now: float) -> None:
        cutoff = now - self._cfg.port_scan_window_s
        for src in list(self._windows.keys()):
            win = self._windows[src]
            win.prune(cutoff)
            fan_out = win.fan_out
            if fan_out == 0:
                del self._windows[src]
                continue
            self._baselines.update(src, fan_out)
            self._baselines.update_population(fan_out)

        cooldown_cutoff = now - self._cfg.port_scan_cooldown_s
        for src in [s for s, t in self._last_alert.items() if t < cooldown_cutoff]:
            del self._last_alert[src]

    def baseline_summary(self) -> dict:
        return {
            "population": self._baselines.population.view("network").to_dict(),
            "tracked_sources": len(self._baselines),
            "current_threshold": round(self._baselines.population.threshold(), 2),
        }

    # ------------------------------------------------------------------ #
    # Alert construction
    # ------------------------------------------------------------------ #

    def _alert(self, now, src, win, fan_out, threshold, baseline, z) -> Alert:
        self._last_alert[src] = now
        cfg = self._cfg
        window = cfg.port_scan_window_s

        tcp_attempts = [a for a in win.attempts if a[3].transport == "TCP"]
        failed = sum(
            1 for a in tcp_attempts
            if a[3].tcp_state in ("RESET", "SYN_SENT", "SYN_RECEIVED")
            and not a[3].handshake_completed
        )
        failed_ratio = failed / len(tcp_attempts) if tcp_attempts else 0.0
        top_target, top_hits = win.host_counts.most_common(1)[0]
        n_targets = len(win.host_counts)
        sample_ports = sorted(win.port_counts.keys())[:20]
        first_ts = win.attempts[0][0] if win.attempts else now
        duration = max(0.0, now - first_ts)
        kind = "vertical scan of one host" if n_targets == 1 else f"sweep across {n_targets} hosts"

        severity = "HIGH" if failed_ratio >= 0.5 or fan_out >= 3 * threshold else "MEDIUM"

        factors = [
            f"{fan_out} distinct destination ports in {duration:.1f}s ({kind}).",
            f"{failed_ratio:.0%} of TCP attempts were refused or unanswered "
            f"({failed}/{len(tcp_attempts)}).",
            f"Sample ports: {', '.join(map(str, sample_ports))}"
            + (" …" if fan_out > len(sample_ports) else ""),
        ]
        if baseline is not None:
            rule = "fan_out ≥ max(floor, μ + k·σ)"
            summary = (
                f"{src} contacted {fan_out} distinct ports in {window:.0f}s; normal for "
                f"{'this host' if baseline.scope == 'per-host' else 'hosts on this network'} "
                f"is {baseline.mean:.1f} ± {baseline.std:.1f}, so the adaptive "
                f"threshold was {threshold:.1f}."
            )
        else:
            rule = f"fan_out ≥ {int(threshold)} (fixed)"
            summary = (
                f"{src} contacted {fan_out} distinct ports in {window:.0f}s, "
                f"above the fixed threshold of {int(threshold)}."
            )

        return Alert(
            timestamp=now,
            alert_type="PORT_SCAN",
            severity=severity,
            mode=self.mode,
            source_ip=src,
            target_ip=top_target,
            description=(
                f"Possible port scan: {src} contacted {fan_out} distinct ports "
                f"within {window:.0f}s."
            ),
            evidence={
                "distinct_ports_contacted": fan_out,
                "distinct_targets": n_targets,
                "primary_target": top_target,
                "primary_target_attempts": top_hits,
                "failed_ratio": round(failed_ratio, 3),
                "window_seconds": window,
                "threshold": round(threshold, 2),
                "sample_ports": sample_ports,
                "duration_seconds": round(duration, 2),
            },
            explanation=explain(
                summary=summary,
                metric=f"distinct destination ports per source in {window:.0f}s",
                observed=fan_out,
                threshold=threshold,
                rule=rule,
                baseline=baseline,
                z_score=z,
                factors=factors,
            ),
        )
