"""
NetVision — SYN Flood Detector (detection/syn_flood.py)

Normal TCP handshake:
    Client → Server : SYN
    Server → Client : SYN-ACK
    Client → Server : ACK    (connection ESTABLISHED)

SYN flood pattern:
    Attacker → Server : SYN  ×  N
    Server → Attacker : SYN-ACK  ×  N   (server holds half-open state)
    Attacker            never sends ACK  (or its kernel answers RST)

Signals (per destination IP)
────────────────────────────
  • SYN count / SYN rate — pure SYN packets to the destination
  • half-open ratio — share of the connection attempts in the window whose
    handshake never completed.  This comes straight from the flow tracker's
    TCP state machine, so it is a statement about *connections*, not a
    guess from flag counts.

Static mode (the report's baseline)
───────────────────────────────────
    SYNs in window ≥ syn_flood_syn_threshold              (default 200 / 10 s)
    AND half-open ratio ≥ syn_flood_incomplete_ratio       (default 0.80)

Adaptive mode
─────────────
    SYN rate ≥ max(floor, μ + k·σ)      (EWMA over 1 s samples, per target
                                         once warmed up, else network-wide)
    AND half-open ratio ≥ syn_flood_adaptive_min_ratio     (default 0.50)

A busy web server sees many SYNs per second but almost all of them
complete, so it fails the half-open test; its own rate baseline also rises.
A flood fails both.

Cost control
────────────
Counts are maintained incrementally.  The half-open ratio (which walks the
window) is only computed when the rate condition holds, and at most every
0.5 s per destination, so a 10 kpps flood does not cost O(window) per packet.

Limitation / honesty
────────────────────
Labelled "Possible SYN Flood": asymmetric routing (we only see one
direction) or a server that is simply down can look similar.
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Optional

from backend.analyzer.flow_tracker import FlowEvent, FlowRecord
from backend.config import Settings, settings as default_settings
from backend.detection.baseline import BaselineTable
from backend.detection.models import Alert, explain
from backend.parser.packet_parser import PacketRecord

_RATIO_EVAL_INTERVAL_S = 0.5
# Attempts younger than this are excluded from the half-open ratio: a
# legitimate handshake needs about one RTT to complete.
_HANDSHAKE_GRACE_S = 0.5


class _TargetWindow:
    __slots__ = ("syns", "rate_syns", "attempts", "sources", "last_ratio_eval",
                 "last_ratio")

    def __init__(self) -> None:
        self.syns: deque[tuple[float, str]] = deque()        # (ts, src_ip) — long window
        self.rate_syns: deque[float] = deque()                # ts — short rate window
        self.attempts: deque[tuple[float, FlowRecord]] = deque()  # connection attempts
        self.sources: Counter = Counter()
        self.last_ratio_eval: float = float("-inf")
        self.last_ratio: tuple[float, int, int] = (0.0, 0, 0)

    def prune(self, now: float, window: float, rate_window: float) -> None:
        cutoff = now - window
        while self.syns and self.syns[0][0] < cutoff:
            _, src = self.syns.popleft()
            self.sources[src] -= 1
            if self.sources[src] <= 0:
                del self.sources[src]
        while self.attempts and self.attempts[0][0] < cutoff:
            self.attempts.popleft()
        rate_cutoff = now - rate_window
        while self.rate_syns and self.rate_syns[0] < rate_cutoff:
            self.rate_syns.popleft()

    def half_open_ratio(self, now: float) -> tuple[float, int, int]:
        """
        (ratio, incomplete, total) over distinct connection attempts older
        than the handshake grace period — a handshake that started 50 ms ago
        is in flight, not half-open.
        """
        seen: set[int] = set()
        total = incomplete = 0
        mature = now - _HANDSHAKE_GRACE_S
        for ts, flow in self.attempts:
            if ts > mature:
                break
            fid = id(flow)
            if fid in seen:
                continue
            seen.add(fid)
            total += 1
            if not flow.handshake_completed:
                incomplete += 1
        return (incomplete / total if total else 0.0), incomplete, total


class SynFloodDetector:
    """Per-destination SYN flood detector (static or adaptive)."""

    def __init__(self, cfg: Settings = default_settings, mode: str = "adaptive") -> None:
        self._cfg = cfg
        self.mode = mode
        self._targets: dict[str, _TargetWindow] = {}
        self._last_alert: dict[str, float] = {}
        self._baselines = BaselineTable(
            alpha=cfg.baseline_alpha,
            k=cfg.baseline_z_threshold,
            warmup=cfg.baseline_warmup_samples,
            floor=cfg.syn_flood_adaptive_floor_rate,
            min_std=2.0,
            # static rule's count expressed as a rate
            cold_clip=cfg.syn_flood_syn_threshold / cfg.syn_flood_window_s,
        )

    # ------------------------------------------------------------------ #
    # Per packet
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord, event: Optional[FlowEvent]) -> Optional[Alert]:
        if not pkt.is_syn or not pkt.dst_ip:
            return None

        cfg = self._cfg
        now = pkt.timestamp
        dst = pkt.dst_ip
        tw = self._targets.get(dst)
        if tw is None:
            tw = self._targets[dst] = _TargetWindow()
        tw.prune(now, cfg.syn_flood_window_s, cfg.syn_flood_rate_window_s)
        tw.syns.append((now, pkt.src_ip or "?"))
        tw.rate_syns.append(now)
        tw.sources[pkt.src_ip or "?"] += 1
        if event is not None and event.connection_attempt:
            tw.attempts.append((now, event.flow))

        if now - self._last_alert.get(dst, float("-inf")) < cfg.syn_flood_cooldown_s:
            return None

        syn_count = len(tw.syns)
        rate = len(tw.rate_syns) / cfg.syn_flood_rate_window_s

        if self.mode == "static":
            if syn_count < cfg.syn_flood_syn_threshold:
                return None
            ratio, incomplete, total = self._ratio(tw, now)
            if ratio < cfg.syn_flood_incomplete_ratio:
                return None
            return self._alert(
                now, dst, tw, syn_count, rate, ratio, incomplete, total,
                threshold=float(cfg.syn_flood_syn_threshold),
                ratio_threshold=cfg.syn_flood_incomplete_ratio,
                baseline=None, z=None,
            )

        baseline, scope = self._baselines.for_key(dst)
        threshold = baseline.threshold()
        if rate < threshold:
            return None
        ratio, incomplete, total = self._ratio(tw, now)
        if ratio < cfg.syn_flood_adaptive_min_ratio:
            return None
        return self._alert(
            now, dst, tw, syn_count, rate, ratio, incomplete, total,
            threshold=threshold,
            ratio_threshold=cfg.syn_flood_adaptive_min_ratio,
            baseline=baseline.view(scope), z=baseline.z_score(rate),
        )

    def _ratio(self, tw: _TargetWindow, now: float) -> tuple[float, int, int]:
        if now - tw.last_ratio_eval >= _RATIO_EVAL_INTERVAL_S:
            tw.last_ratio = tw.half_open_ratio(now)
            tw.last_ratio_eval = now
        return tw.last_ratio

    # ------------------------------------------------------------------ #
    # Per tick — learn SYN-rate baselines
    # ------------------------------------------------------------------ #

    def tick(self, now: float) -> None:
        cfg = self._cfg
        for dst in list(self._targets.keys()):
            tw = self._targets[dst]
            tw.prune(now, cfg.syn_flood_window_s, cfg.syn_flood_rate_window_s)
            if not tw.syns:
                del self._targets[dst]
                continue
            rate = len(tw.rate_syns) / cfg.syn_flood_rate_window_s
            self._baselines.update(dst, rate)
            self._baselines.update_population(rate)

        cooldown_cutoff = now - cfg.syn_flood_cooldown_s
        for dst in [d for d, t in self._last_alert.items() if t < cooldown_cutoff]:
            del self._last_alert[dst]

    def baseline_summary(self) -> dict:
        return {
            "population": self._baselines.population.view("network").to_dict(),
            "tracked_targets": len(self._baselines),
            "current_threshold": round(self._baselines.population.threshold(), 2),
        }

    # ------------------------------------------------------------------ #
    # Alert construction
    # ------------------------------------------------------------------ #

    def _alert(
        self, now, dst, tw, syn_count, rate, ratio, incomplete, total,
        threshold, ratio_threshold, baseline, z,
    ) -> Alert:
        self._last_alert[dst] = now
        cfg = self._cfg
        n_sources = len(tw.sources)
        top_src, top_n = tw.sources.most_common(1)[0] if tw.sources else (None, 0)
        target_ports = Counter(f.dst_port for _, f in tw.attempts)
        top_port = target_ports.most_common(1)[0][0] if target_ports else None
        spoofed_hint = n_sources > 50

        factors = [
            f"{syn_count} SYNs to {dst} in {cfg.syn_flood_window_s:.0f}s "
            f"({rate:.0f} SYN/s over the last {cfg.syn_flood_rate_window_s:.0f}s).",
            f"{incomplete} of {total} connection attempts never completed the "
            f"handshake ({ratio:.0%} half-open, rule needs ≥ {ratio_threshold:.0%}).",
            f"{n_sources} distinct source address(es)"
            + (" — many sources suggests spoofed or distributed origin." if spoofed_hint else "."),
        ]
        if top_port is not None:
            factors.append(f"Most targeted port: {top_port}.")

        if baseline is not None:
            metric = f"SYN rate to one destination (SYN/s, {cfg.syn_flood_rate_window_s:.0f}s window)"
            observed = rate
            rule = "rate ≥ max(floor, μ + k·σ) AND half_open_ratio ≥ min_ratio"
            summary = (
                f"{dst} is receiving {rate:.0f} SYN/s against a normal "
                f"{baseline.mean:.1f} ± {baseline.std:.1f} SYN/s (threshold "
                f"{threshold:.1f}), and {ratio:.0%} of those connections are "
                f"left half-open."
            )
        else:
            metric = f"SYNs to one destination in {cfg.syn_flood_window_s:.0f}s"
            observed = syn_count
            rule = (f"syn_count ≥ {int(threshold)} AND half_open_ratio ≥ "
                    f"{ratio_threshold:.0%} (fixed)")
            summary = (
                f"{dst} received {syn_count} SYNs in {cfg.syn_flood_window_s:.0f}s "
                f"(fixed threshold {int(threshold)}) and {ratio:.0%} of the "
                f"connections were never completed."
            )

        return Alert(
            timestamp=now,
            alert_type="SYN_FLOOD",
            severity="CRITICAL" if ratio >= 0.95 and rate >= 10 * max(threshold, 1) else "HIGH",
            mode=self.mode,
            source_ip=top_src if n_sources <= 3 else f"{n_sources} sources",
            target_ip=dst,
            description=(
                f"Possible SYN flood targeting {dst}: {syn_count} SYNs, "
                f"{incomplete}/{total} handshakes incomplete ({ratio:.0%})."
            ),
            evidence={
                "syn_count": syn_count,
                "syn_rate_per_s": round(rate, 1),
                "completed_count": total - incomplete,
                "incomplete_count": incomplete,
                "incomplete_ratio": round(ratio, 3),
                "distinct_sources": n_sources,
                "top_source": top_src,
                "top_source_syns": top_n,
                "target_port": top_port,
                "window_seconds": cfg.syn_flood_window_s,
                "threshold": round(threshold, 2),
            },
            explanation=explain(
                summary=summary, metric=metric, observed=observed,
                threshold=threshold, rule=rule, baseline=baseline, z_score=z,
                factors=factors,
            ),
        )
