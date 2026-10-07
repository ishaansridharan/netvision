"""
NetVision — Statistics Engine (analyzer/stats_engine.py)

Consumes the packet stream and, on every tick, produces a StatsSnapshot:

  • Download / upload / LAN bandwidth (bytes/sec, rolling window)
  • 1-second throughput (fed to the traffic-spike detector)
  • Packets per second
  • Protocol distribution (rolling window)
  • Top talkers / top destinations (rolling window, with share of traffic)
  • Latency — median and p95 of RTT samples from ICMP echo pairs and TCP
    handshakes
  • Jitter — mean absolute difference between consecutive RTT samples to
    the same host (RFC 3550 style "RTT variation"), averaged over hosts
  • Packet loss estimate — TCP retransmission rate
  • Network Health Score (0–100) with a per-component explanation

Rolling window approach
───────────────────────
Packets are aggregated into 1-second buckets.  A snapshot merges the last
`stats_rolling_window_s` buckets, so snapshot cost does not grow with the
packet rate.

Time base
─────────
Everything is keyed on packet timestamps and the `now` passed to tick(),
never on time.time().  The live server ticks with wall-clock time; the
evaluation harness ticks with pcap time.  Both get identical behaviour.

Health Score composition
────────────────────────
Each component scores 0–1 and carries a configurable weight:
  latency, packet loss, bandwidth utilisation, active threats.
Components with no data (e.g. no RTT samples yet) are left out and the
remaining weights are renormalised — "unknown" is not reported as "good".
"""

from __future__ import annotations

import logging
import statistics
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from backend.analyzer.flow_tracker import FlowEvent, FlowTracker
from backend.analyzer.hosts import DOWNLOAD, UPLOAD, HostRegistry
from backend.config import Settings, settings as default_settings
from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)

_ICMP_PENDING_TTL_S = 5.0
_SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ──────────────────────────────────────────────────────────────────────────
# Per-second aggregation bucket
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class _Bucket:
    second: int
    packets: int = 0
    bytes: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    bytes_lan: int = 0
    tcp_data_segments: int = 0
    tcp_retransmissions: int = 0
    protocols: dict = field(default_factory=lambda: defaultdict(int))
    src_bytes: dict = field(default_factory=lambda: defaultdict(int))
    dst_bytes: dict = field(default_factory=lambda: defaultdict(int))


# ──────────────────────────────────────────────────────────────────────────
# Snapshot data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class StatsSnapshot:
    """Immutable snapshot of network statistics at a point in time."""

    timestamp: float
    download_bps: float
    upload_bps: float
    lan_bps: float
    instant_bps: float               # throughput of the last full second
    packets_per_sec: float
    protocol_dist: dict
    top_talkers: list[dict]
    top_destinations: list[dict]
    latency_ms: Optional[float]
    latency_p95_ms: Optional[float]
    jitter_ms: Optional[float]
    rtt_samples: int
    packet_loss_pct: Optional[float]
    retransmissions: int
    active_connections: int
    half_open_connections: int
    tcp_states: dict
    host_count: int
    health_score: int
    health: dict
    total_packets: int
    total_bytes: int
    interval_packets: int            # since the previous snapshot
    interval_bytes: int

    @property
    def total_bps(self) -> float:
        return self.download_bps + self.upload_bps + self.lan_bps

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "download_bps": round(self.download_bps),
            "upload_bps": round(self.upload_bps),
            "lan_bps": round(self.lan_bps),
            "total_bps": round(self.total_bps),
            "instant_bps": round(self.instant_bps),
            "download_mbps": round(self.download_bps * 8 / 1_000_000, 3),
            "upload_mbps": round(self.upload_bps * 8 / 1_000_000, 3),
            "total_mbps": round(self.total_bps * 8 / 1_000_000, 3),
            "packets_per_sec": round(self.packets_per_sec, 1),
            "protocol_dist": self.protocol_dist,
            "top_talkers": self.top_talkers,
            "top_destinations": self.top_destinations,
            "latency_ms": _r(self.latency_ms),
            "latency_p95_ms": _r(self.latency_p95_ms),
            "jitter_ms": _r(self.jitter_ms),
            "rtt_samples": self.rtt_samples,
            "packet_loss_pct": _r(self.packet_loss_pct),
            "retransmissions": self.retransmissions,
            "active_connections": self.active_connections,
            "half_open_connections": self.half_open_connections,
            "tcp_states": self.tcp_states,
            "host_count": self.host_count,
            "health_score": self.health_score,
            "health": self.health,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "interval_packets": self.interval_packets,
            "interval_bytes": self.interval_bytes,
        }


def _r(v: Optional[float], nd: int = 2) -> Optional[float]:
    return round(v, nd) if v is not None else None


# ──────────────────────────────────────────────────────────────────────────
# Statistics Engine
# ──────────────────────────────────────────────────────────────────────────

class StatsEngine:
    """
    Ingests PacketRecords (+ their FlowEvents) and produces a StatsSnapshot
    on every tick().

    Usage
    ─────
        engine = StatsEngine(cfg, hosts, flow_tracker, recent_alerts_fn)
        engine.process(pkt, flow_event)      # per packet
        snap = engine.tick(now)              # once per interval
        engine.latest_snapshot(); engine.history()
    """

    def __init__(
        self,
        cfg: Settings = default_settings,
        hosts: Optional[HostRegistry] = None,
        flow_tracker: Optional[FlowTracker] = None,
        recent_alerts_fn: Optional[Callable[[float, float], list]] = None,
    ) -> None:
        self._cfg = cfg
        self._hosts = hosts or HostRegistry(cfg.max_tracked_hosts, cfg.local_networks)
        self._flow_tracker = flow_tracker
        # (now, horizon_s) → list of unresolved alerts within the horizon
        self._recent_alerts_fn = recent_alerts_fn or (lambda now, horizon: [])

        self._lock = threading.Lock()

        self._buckets: deque[_Bucket] = deque()

        # ICMP echo matching: (src, dst, id, seq) → request timestamp
        self._icmp_pending: dict[tuple, float] = {}

        # RTT samples: (timestamp, rtt_ms, peer_ip)
        self._rtt_samples: deque[tuple[float, float, str]] = deque(maxlen=5_000)

        # Totals
        self._total_packets = 0
        self._total_bytes = 0
        self._last_total_packets = 0
        self._last_total_bytes = 0

        # Snapshot history ring
        self._history: deque[StatsSnapshot] = deque(maxlen=cfg.stats_history_max)
        self._latest: Optional[StatsSnapshot] = None

    @property
    def hosts(self) -> HostRegistry:
        return self._hosts

    # ------------------------------------------------------------------ #
    # Packet ingestion
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord, event: Optional[FlowEvent] = None) -> None:
        """Update all running accumulators with a new packet."""
        now = pkt.timestamp
        direction = self._hosts.direction(pkt)

        with self._lock:
            bucket = self._bucket_for(now)
            size = pkt.size

            self._total_packets += 1
            self._total_bytes += size

            bucket.packets += 1
            bucket.bytes += size
            if direction == UPLOAD:
                bucket.bytes_up += size
            elif direction == DOWNLOAD:
                bucket.bytes_down += size
            else:
                bucket.bytes_lan += size

            bucket.protocols[pkt.protocol] += 1
            if pkt.src_ip:
                bucket.src_bytes[pkt.src_ip] += size
            if pkt.dst_ip:
                bucket.dst_bytes[pkt.dst_ip] += size

            if event is not None:
                if event.is_data:
                    bucket.tcp_data_segments += 1
                if event.retransmission:
                    bucket.tcp_retransmissions += 1
                if event.rtt_sample_ms is not None:
                    # Attribute the RTT to the remote end of the connection
                    flow = event.flow
                    peer = flow.dst_ip
                    if self._hosts.is_local(peer) and not self._hosts.is_local(flow.src_ip):
                        peer = flow.src_ip
                    self._rtt_samples.append((now, event.rtt_sample_ms, peer))

            if pkt.transport == "ICMP":
                self._measure_icmp_rtt(pkt, now)

    def _bucket_for(self, ts: float) -> _Bucket:
        second = int(ts)
        if self._buckets and self._buckets[-1].second >= second:
            # Same second, or a slightly out-of-order packet: account it to
            # the newest bucket rather than re-opening an old one.
            return self._buckets[-1]
        bucket = _Bucket(second=second)
        self._buckets.append(bucket)
        return bucket

    def _measure_icmp_rtt(self, pkt: PacketRecord, now: float) -> None:
        """Match ICMP echo requests (type 8) with replies (type 0) by id/seq."""
        if pkt.icmp_type == 8:
            key = (pkt.src_ip, pkt.dst_ip, pkt.icmp_id, pkt.icmp_seq)
            self._icmp_pending[key] = now
        elif pkt.icmp_type == 0:
            key = (pkt.dst_ip, pkt.src_ip, pkt.icmp_id, pkt.icmp_seq)
            sent = self._icmp_pending.pop(key, None)
            if sent is not None:
                rtt_ms = (now - sent) * 1000
                if 0 <= rtt_ms < 5000:
                    self._rtt_samples.append((now, rtt_ms, pkt.src_ip))

    # ------------------------------------------------------------------ #
    # Public accessors
    # ------------------------------------------------------------------ #

    def latest_snapshot(self) -> Optional[StatsSnapshot]:
        return self._latest

    def history(self, limit: int = 300) -> list[dict]:
        """Return last *limit* snapshots as dicts (oldest first)."""
        snaps = list(self._history)
        return [s.to_dict() for s in snaps[-limit:]]

    # ------------------------------------------------------------------ #
    # Snapshot
    # ------------------------------------------------------------------ #

    def tick(self, now: float) -> StatsSnapshot:
        snap = self._compute_snapshot(now)
        self._latest = snap
        self._history.append(snap)
        return snap

    def _compute_snapshot(self, now: float) -> StatsSnapshot:
        cfg = self._cfg
        window = cfg.stats_rolling_window_s
        oldest_second = int(now - window)
        last_full_second = int(now) - 1

        with self._lock:
            while self._buckets and self._buckets[0].second < oldest_second:
                self._buckets.popleft()
            # Only seconds strictly before `now` are complete.
            buckets = [b for b in self._buckets if b.second < int(now)]

            # Expire unanswered pings
            cutoff = now - _ICMP_PENDING_TTL_S
            if self._icmp_pending:
                for k in [k for k, t in self._icmp_pending.items() if t < cutoff]:
                    del self._icmp_pending[k]

            rtt_cutoff = now - cfg.latency_window_s
            while self._rtt_samples and self._rtt_samples[0][0] < rtt_cutoff:
                self._rtt_samples.popleft()
            rtts = list(self._rtt_samples)

            total_pkts = self._total_packets
            total_bytes = self._total_bytes
            interval_packets = total_pkts - self._last_total_packets
            interval_bytes = total_bytes - self._last_total_bytes
            self._last_total_packets = total_pkts
            self._last_total_bytes = total_bytes

        span = window
        dl = sum(b.bytes_down for b in buckets) / span
        ul = sum(b.bytes_up for b in buckets) / span
        lan = sum(b.bytes_lan for b in buckets) / span
        pps = sum(b.packets for b in buckets) / span
        instant = next(
            (b.bytes for b in reversed(buckets) if b.second == last_full_second), 0
        )

        protocols: dict[str, int] = defaultdict(int)
        src_bytes: dict[str, int] = defaultdict(int)
        dst_bytes: dict[str, int] = defaultdict(int)
        data_segs = retrans = 0
        for b in buckets:
            for p, c in b.protocols.items():
                protocols[p] += c
            for ip, n in b.src_bytes.items():
                src_bytes[ip] += n
            for ip, n in b.dst_bytes.items():
                dst_bytes[ip] += n
            data_segs += b.tcp_data_segments
            retrans += b.tcp_retransmissions

        window_bytes = sum(b.bytes for b in buckets)
        proto_total = sum(protocols.values())
        protocol_dist = {
            p: {"count": c, "pct": round(c / proto_total * 100, 1)}
            for p, c in sorted(protocols.items(), key=lambda kv: -kv[1])
        }
        top_talkers = self._rank(src_bytes, window_bytes)
        top_dests = self._rank(dst_bytes, window_bytes)

        latency, p95, jitter = _rtt_summary(rtts)
        loss = (
            retrans / data_segs * 100
            if data_segs >= cfg.loss_min_segments else None
        )

        flow_stats = self._flow_tracker.get_stats() if self._flow_tracker else {}
        alerts = self._recent_alerts_fn(now, cfg.health_alert_horizon_s)

        health = self._compute_health(
            latency_ms=latency, loss_pct=loss, total_bps=dl + ul + lan,
            alerts=alerts, top_talkers=top_talkers,
            rtt_count=len(rtts), data_segs=data_segs, retrans=retrans,
        )

        return StatsSnapshot(
            timestamp=now,
            download_bps=dl,
            upload_bps=ul,
            lan_bps=lan,
            instant_bps=float(instant),
            packets_per_sec=pps,
            protocol_dist=protocol_dist,
            top_talkers=top_talkers,
            top_destinations=top_dests,
            latency_ms=latency,
            latency_p95_ms=p95,
            jitter_ms=jitter,
            rtt_samples=len(rtts),
            packet_loss_pct=loss,
            retransmissions=retrans,
            active_connections=flow_stats.get("active_flows", 0),
            half_open_connections=flow_stats.get("half_open_flows", 0),
            tcp_states=flow_stats.get("tcp_states", {}),
            host_count=self._hosts.count(),
            health_score=health["score"],
            health=health,
            total_packets=total_pkts,
            total_bytes=total_bytes,
            interval_packets=interval_packets,
            interval_bytes=interval_bytes,
        )

    def _rank(self, by_ip: dict[str, int], window_bytes: int, n: int = 10) -> list[dict]:
        ranked = sorted(by_ip.items(), key=lambda kv: -kv[1])[:n]
        return [
            {
                "ip": ip,
                "name": self._hosts.name_of(ip),
                "bytes": b,
                "bps": round(b / self._cfg.stats_rolling_window_s),
                "pct": round(b / window_bytes * 100, 1) if window_bytes else 0.0,
                "scope": "local" if self._hosts.is_local(ip) else "external",
            }
            for ip, b in ranked
        ]

    # ------------------------------------------------------------------ #
    # Health score
    # ------------------------------------------------------------------ #

    def _compute_health(
        self,
        latency_ms: Optional[float],
        loss_pct: Optional[float],
        total_bps: float,
        alerts: list,
        top_talkers: list[dict],
        rtt_count: int,
        data_segs: int,
        retrans: int,
    ) -> dict:
        """
        Returns {"score": 0–100, "components": [...], "issues": [...]}.
        Every component explains its own value so the dashboard can answer
        "why is my network health 72?".
        """
        cfg = self._cfg
        components: list[dict] = []

        # Latency
        if latency_ms is None:
            components.append(_component(
                "latency", None, cfg.health_weight_latency, None, "ms",
                "No RTT samples yet (needs ICMP echo or new TCP connections).",
            ))
        else:
            s = _linear(latency_ms, cfg.health_latency_good_ms, cfg.health_latency_bad_ms)
            components.append(_component(
                "latency", s, cfg.health_weight_latency, round(latency_ms, 1), "ms",
                f"Median RTT {latency_ms:.1f} ms over {rtt_count} samples "
                f"(good ≤ {cfg.health_latency_good_ms:.0f} ms, "
                f"bad ≥ {cfg.health_latency_bad_ms:.0f} ms).",
            ))

        # Packet loss
        if loss_pct is None:
            components.append(_component(
                "packet_loss", None, cfg.health_weight_packet_loss, None, "%",
                f"Not enough TCP data in the window to estimate loss "
                f"({data_segs}/{cfg.loss_min_segments} segments).",
            ))
        else:
            s = _linear(loss_pct, cfg.health_loss_good_pct, cfg.health_loss_bad_pct)
            components.append(_component(
                "packet_loss", s, cfg.health_weight_packet_loss, round(loss_pct, 2), "%",
                f"{retrans} retransmitted of {data_segs} TCP data segments "
                f"({loss_pct:.2f}%).",
            ))

        # Bandwidth utilisation
        capacity_bps = cfg.interface_capacity_mbps * 1_000_000 / 8
        util = min(total_bps / capacity_bps * 100, 100.0) if capacity_bps else 0.0
        s = _linear(util, cfg.health_bandwidth_good_pct, cfg.health_bandwidth_bad_pct)
        reason = (
            f"{total_bps * 8 / 1e6:.2f} Mbit/s = {util:.1f}% of the assumed "
            f"{cfg.interface_capacity_mbps:.0f} Mbit/s link."
        )
        culprit = None
        if top_talkers and top_talkers[0]["pct"] >= 30 and util >= cfg.health_bandwidth_good_pct:
            culprit = top_talkers[0]
            reason += f" {culprit['name']} accounts for {culprit['pct']:.0f}% of traffic."
        comp = _component(
            "bandwidth", s, cfg.health_weight_bandwidth, round(util, 1), "%", reason
        )
        if culprit:
            comp["culprit"] = {"ip": culprit["ip"], "name": culprit["name"], "pct": culprit["pct"]}
        components.append(comp)

        # Threats
        penalty = sum(_SEVERITY_WEIGHT.get(getattr(a, "severity", "MEDIUM"), 2) for a in alerts)
        s = max(0.0, 1.0 - penalty / 8.0)   # two HIGH alerts (+ a LOW) → 0
        if alerts:
            kinds = sorted({getattr(a, "alert_type", "?") for a in alerts})
            reason = (
                f"{len(alerts)} unresolved alert(s) in the last "
                f"{cfg.health_alert_horizon_s / 60:.0f} min: {', '.join(kinds)}."
            )
        else:
            reason = "No unresolved alerts."
        components.append(_component(
            "threats", s, cfg.health_weight_threats, len(alerts), "alerts", reason
        ))

        known = [c for c in components if c["score"] is not None]
        weight_sum = sum(c["weight"] for c in known)
        score = (
            round(sum(c["score"] * c["weight"] for c in known) / weight_sum * 100)
            if weight_sum else 100
        )
        for c in components:
            c["effective_weight"] = (
                round(c["weight"] / weight_sum, 3) if c["score"] is not None and weight_sum else 0.0
            )
            c["points_lost"] = (
                round((1 - c["score"]) * c["effective_weight"] * 100, 1)
                if c["score"] is not None else 0.0
            )

        issues = [
            c["reason"] for c in sorted(known, key=lambda c: -c["points_lost"])
            if c["points_lost"] >= 1
        ]
        return {
            "score": max(0, min(100, score)),
            "components": components,
            "issues": issues,
        }


# ──────────────────────────────────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────────────────────────────────

def _component(name, score, weight, value, unit, reason) -> dict:
    if score is None:
        status = "unknown"
    elif score >= 0.8:
        status = "good"
    elif score >= 0.4:
        status = "degraded"
    else:
        status = "bad"
    return {
        "name": name,
        "score": round(score, 3) if score is not None else None,
        "weight": weight,
        "value": value,
        "unit": unit,
        "status": status,
        "reason": reason,
    }


def _linear(value: float, good: float, bad: float) -> float:
    """1.0 at/below *good*, 0.0 at/above *bad*, linear in between."""
    if bad == good:
        return 1.0 if value <= good else 0.0
    ratio = (value - good) / (bad - good)
    return 1.0 - max(0.0, min(1.0, ratio))


def _rtt_summary(
    samples: list[tuple[float, float, str]],
) -> tuple[Optional[float], Optional[float], Optional[float]]:
    """Return (median, p95, jitter) in ms; None when there are no samples."""
    if not samples:
        return None, None, None
    values = sorted(s[1] for s in samples)
    median = statistics.median(values)
    p95 = values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))]

    # Jitter: consecutive RTT differences per peer, so a LAN host and a
    # far-away server don't look like jitter when interleaved.
    last_by_peer: dict[str, float] = {}
    diffs: list[float] = []
    for _, rtt, peer in samples:
        prev = last_by_peer.get(peer)
        if prev is not None:
            diffs.append(abs(rtt - prev))
        last_by_peer[peer] = rtt
    jitter = sum(diffs) / len(diffs) if diffs else None
    return median, p95, jitter
