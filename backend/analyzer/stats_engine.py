"""
NetVision — Statistics Engine (analyzer/stats_engine.py)

Consumes the packet stream and continuously calculates:

  • Download / upload bandwidth (bytes/sec)
  • Packets per second
  • Protocol distribution
  • Top talkers (src IPs by bytes)
  • Top destinations (dst IPs by bytes)
  • Latency estimation (ICMP echo RTT, TCP SYN→SYN-ACK timing)
  • Packet loss estimation (TCP duplicate ACKs)
  • Jitter (inter-packet arrival time variance per flow)
  • Network Health Score (0–100)

Rolling window approach
───────────────────────
A deque of (timestamp, bytes) tuples is maintained.  On each snapshot
the deque is pruned to only include entries within the rolling window.
Bandwidth = sum(bytes in window) / window_seconds.

Health Score composition
────────────────────────
  score = 100
  - latency_penalty   (0–25 pts)
  - loss_penalty      (0–25 pts)
  - bandwidth_penalty (0–25 pts)
  - threat_penalty    (0–25 pts)
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from backend.config import settings
from backend.analyzer.protocol_stats import ProtocolStats
from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────
# Snapshot data model
# ──────────────────────────────────────────────────────────────────────────

class StatsSnapshot:
    """Immutable snapshot of network statistics at a point in time."""

    def __init__(
        self,
        timestamp: float,
        download_bps: float,
        upload_bps: float,
        packets_per_sec: float,
        protocol_dist: dict,
        top_talkers: list[dict],
        top_destinations: list[dict],
        latency_ms: Optional[float],
        packet_loss_pct: float,
        jitter_ms: float,
        active_connections: int,
        health_score: int,
        total_packets: int,
        total_bytes: int,
    ):
        self.timestamp = timestamp
        self.download_bps = download_bps
        self.upload_bps = upload_bps
        self.packets_per_sec = packets_per_sec
        self.protocol_dist = protocol_dist
        self.top_talkers = top_talkers
        self.top_destinations = top_destinations
        self.latency_ms = latency_ms
        self.packet_loss_pct = packet_loss_pct
        self.jitter_ms = jitter_ms
        self.active_connections = active_connections
        self.health_score = health_score
        self.total_packets = total_packets
        self.total_bytes = total_bytes

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "download_bps": round(self.download_bps),
            "upload_bps": round(self.upload_bps),
            "download_mbps": round(self.download_bps / 1_000_000, 2),
            "upload_mbps": round(self.upload_bps / 1_000_000, 2),
            "packets_per_sec": round(self.packets_per_sec, 1),
            "protocol_dist": self.protocol_dist,
            "top_talkers": self.top_talkers,
            "top_destinations": self.top_destinations,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "packet_loss_pct": round(self.packet_loss_pct, 2),
            "jitter_ms": round(self.jitter_ms, 2),
            "active_connections": self.active_connections,
            "health_score": self.health_score,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
        }


# ──────────────────────────────────────────────────────────────────────────
# Statistics Engine
# ──────────────────────────────────────────────────────────────────────────

class StatsEngine:
    """
    Ingests PacketRecords and produces StatsSnapshots on a regular interval.

    Usage
    ─────
        engine = StatsEngine(flow_tracker, active_alert_count_fn)
        engine.start()
        engine.process(packet_record)
        latest = engine.latest_snapshot()
        history = engine.history()
    """

    def __init__(
        self,
        flow_tracker=None,
        active_alert_count_fn=None,
        local_subnet_prefix: str = "192.168.",  # crude local subnet heuristic
    ) -> None:
        self._flow_tracker = flow_tracker
        self._alert_count_fn = active_alert_count_fn or (lambda: 0)
        self._local_prefix = local_subnet_prefix

        self._lock = threading.Lock()

        # Rolling window: deque of (timestamp, bytes, is_download)
        self._window: deque[tuple[float, int, bool]] = deque()

        # Per-IP byte accumulators (all-time for top-talker ranking)
        self._src_bytes: dict[str, int] = defaultdict(int)
        self._dst_bytes: dict[str, int] = defaultdict(int)

        # Protocol stats (rolling window — reset each snapshot cycle)
        self._proto_stats = ProtocolStats()

        # Latency measurement via ICMP echo pair matching
        # { (src_ip, dst_ip, icmp_id, seq) : request_timestamp }
        self._icmp_requests: dict[tuple, float] = {}
        self._latency_samples: deque[float] = deque(maxlen=100)

        # TCP SYN→SYN-ACK RTT
        # { (src_ip, dst_ip, src_port, dst_port) : syn_timestamp }
        self._tcp_syn_times: dict[tuple, float] = {}

        # Jitter: inter-packet arrival times per flow key
        self._last_pkt_time: dict[str, float] = {}
        self._ipt_samples: deque[float] = deque(maxlen=200)

        # Packet loss: track TCP retransmission signals
        self._tcp_total: int = 0
        self._tcp_dup_acks: int = 0

        # Total counters
        self._total_packets: int = 0
        self._total_bytes: int = 0

        # Snapshot history ring
        self._history: deque[StatsSnapshot] = deque(
            maxlen=settings.stats_history_max
        )
        self._latest: Optional[StatsSnapshot] = None

        self._snapshot_thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        self._running = True
        self._snapshot_thread = threading.Thread(
            target=self._snapshot_loop,
            name="netvision-stats",
            daemon=True,
        )
        self._snapshot_thread.start()
        logger.info("StatsEngine started.")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------ #
    # Packet ingestion (called from capture thread via callback)
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord) -> None:
        """Update all running accumulators with a new packet."""
        now = pkt.timestamp
        is_download = self._is_download(pkt)

        with self._lock:
            self._total_packets += 1
            self._total_bytes += pkt.size

            # Rolling window entry
            self._window.append((now, pkt.size, is_download))

            # Per-IP accounting
            if pkt.src_ip:
                self._src_bytes[pkt.src_ip] += pkt.size
            if pkt.dst_ip:
                self._dst_bytes[pkt.dst_ip] += pkt.size

            # Protocol distribution
            self._proto_stats.record(pkt.protocol)

            # Latency — ICMP
            self._measure_icmp_rtt(pkt, now)

            # Latency — TCP SYN timing
            self._measure_tcp_rtt(pkt, now)

            # Jitter
            self._measure_jitter(pkt, now)

            # Packet loss heuristic
            self._measure_loss(pkt)

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
    # Snapshot loop
    # ------------------------------------------------------------------ #

    def _snapshot_loop(self) -> None:
        while self._running:
            time.sleep(settings.stats_snapshot_interval_s)
            snap = self._compute_snapshot()
            self._latest = snap
            self._history.append(snap)

    def _compute_snapshot(self) -> StatsSnapshot:
        now = time.time()
        window = settings.stats_rolling_window_s
        cutoff = now - window

        with self._lock:
            # Prune old window entries
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()

            dl_bytes = sum(b for ts, b, dl in self._window if dl and ts >= cutoff)
            ul_bytes = sum(b for ts, b, dl in self._window if not dl and ts >= cutoff)
            pkt_count = len(self._window)

            dl_bps = dl_bytes / window
            ul_bps = ul_bytes / window
            pps = pkt_count / window

            proto_dist = self._proto_stats.snapshot()

            # Top talkers — top 10 source IPs
            top_talkers = sorted(
                [{"ip": ip, "bytes": b} for ip, b in self._src_bytes.items()],
                key=lambda x: -x["bytes"],
            )[:10]

            # Top destinations — top 10 destination IPs
            top_dests = sorted(
                [{"ip": ip, "bytes": b} for ip, b in self._dst_bytes.items()],
                key=lambda x: -x["bytes"],
            )[:10]

            # Latency
            latency = (
                sum(self._latency_samples) / len(self._latency_samples)
                if self._latency_samples else None
            )

            # Jitter (mean absolute deviation of inter-packet times)
            jitter = (
                _mean_absolute_deviation(list(self._ipt_samples))
                if len(self._ipt_samples) > 1 else 0.0
            )

            # Packet loss
            loss_pct = (
                (self._tcp_dup_acks / self._tcp_total * 100)
                if self._tcp_total > 0 else 0.0
            )

            total_pkts = self._total_packets
            total_bytes = self._total_bytes

        # Active connections from flow tracker
        active_conns = 0
        if self._flow_tracker:
            stats = self._flow_tracker.get_stats()
            active_conns = stats.get("active_flows", 0)

        # Alert count
        alert_count = self._alert_count_fn()

        # Health score
        health = self._compute_health(latency, loss_pct, dl_bps + ul_bps, alert_count)

        return StatsSnapshot(
            timestamp=now,
            download_bps=dl_bps,
            upload_bps=ul_bps,
            packets_per_sec=pps,
            protocol_dist=proto_dist,
            top_talkers=top_talkers,
            top_destinations=top_dests,
            latency_ms=latency,
            packet_loss_pct=loss_pct,
            jitter_ms=jitter * 1000,
            active_connections=active_conns,
            health_score=health,
            total_packets=total_pkts,
            total_bytes=total_bytes,
        )

    # ------------------------------------------------------------------ #
    # Measurement helpers
    # ------------------------------------------------------------------ #

    def _is_download(self, pkt: PacketRecord) -> bool:
        """
        Heuristic: a packet is a download if its destination IP is on the
        local subnet (i.e., traffic flowing *to* a local device).
        """
        if pkt.dst_ip and pkt.dst_ip.startswith(self._local_prefix):
            return True
        return False

    def _measure_icmp_rtt(self, pkt: PacketRecord, now: float) -> None:
        """Match ICMP echo requests (type 8) with replies (type 0) for RTT."""
        if pkt.protocol != "ICMP":
            return
        if pkt.icmp_type == 8:  # Echo Request
            key = (pkt.src_ip, pkt.dst_ip, pkt.icmp_type)
            self._icmp_requests[key] = now
        elif pkt.icmp_type == 0:  # Echo Reply
            req_key = (pkt.dst_ip, pkt.src_ip, 8)
            if req_key in self._icmp_requests:
                rtt_ms = (now - self._icmp_requests.pop(req_key)) * 1000
                if 0 < rtt_ms < 5000:  # Sanity check
                    self._latency_samples.append(rtt_ms)

    def _measure_tcp_rtt(self, pkt: PacketRecord, now: float) -> None:
        """Match TCP SYN with SYN-ACK for RTT estimate."""
        if pkt.protocol != "TCP":
            return
        flags = pkt.tcp_flags or ""
        if flags == "SYN":
            key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
            self._tcp_syn_times[key] = now
        elif flags == "SYN-ACK":
            rev_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port)
            if rev_key in self._tcp_syn_times:
                rtt_ms = (now - self._tcp_syn_times.pop(rev_key)) * 1000
                if 0 < rtt_ms < 5000:
                    self._latency_samples.append(rtt_ms)

    def _measure_jitter(self, pkt: PacketRecord, now: float) -> None:
        """Track inter-packet arrival time for jitter calculation."""
        flow_key = f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}"
        if flow_key in self._last_pkt_time:
            ipt = now - self._last_pkt_time[flow_key]
            if 0 < ipt < 1.0:  # Only sub-second gaps are meaningful for jitter
                self._ipt_samples.append(ipt)
        self._last_pkt_time[flow_key] = now

    def _measure_loss(self, pkt: PacketRecord) -> None:
        """
        Heuristic packet loss: count TCP duplicate ACKs as a proxy.
        A duplicate ACK has the same ACK number as the previous one seen
        for that flow — we don't maintain per-flow SEQ state here, so we
        use the simpler heuristic of ACK-only packets with no data payload.
        """
        if pkt.protocol != "TCP":
            return
        self._tcp_total += 1
        if pkt.tcp_flags == "ACK" and pkt.size <= 60:
            self._tcp_dup_acks += 1

    # ------------------------------------------------------------------ #
    # Health score
    # ------------------------------------------------------------------ #

    def _compute_health(
        self,
        latency_ms: Optional[float],
        loss_pct: float,
        total_bps: float,
        alert_count: int,
    ) -> int:
        """
        Returns 0–100.  Each component contributes up to 25 points.
        """
        cfg = settings

        # Latency component
        if latency_ms is None:
            latency_score = 25  # Unknown → assume good
        else:
            latency_score = _linear_score(
                latency_ms,
                good=cfg.health_latency_good_ms,
                bad=cfg.health_latency_bad_ms,
                max_pts=25,
                invert=True,
            )

        # Packet loss component
        loss_score = _linear_score(
            loss_pct,
            good=cfg.health_loss_good_pct,
            bad=cfg.health_loss_bad_pct,
            max_pts=25,
            invert=True,
        )

        # Bandwidth utilisation component
        capacity_bps = cfg.interface_capacity_mbps * 1_000_000
        utilisation_pct = min(total_bps / capacity_bps * 100, 100) if capacity_bps else 0
        bw_score = _linear_score(
            utilisation_pct,
            good=cfg.health_bandwidth_good_pct,
            bad=cfg.health_bandwidth_bad_pct,
            max_pts=25,
            invert=True,
        )

        # Threat component
        if alert_count == 0:
            threat_score = 25
        elif alert_count <= 2:
            threat_score = 15
        elif alert_count <= 5:
            threat_score = 8
        else:
            threat_score = 0

        total = latency_score + loss_score + bw_score + threat_score
        return max(0, min(100, total))


# ──────────────────────────────────────────────────────────────────────────
# Utility functions
# ──────────────────────────────────────────────────────────────────────────

def _linear_score(
    value: float, good: float, bad: float, max_pts: int, invert: bool = True
) -> int:
    """
    Map *value* linearly between *good* and *bad* to [0, max_pts].
    If invert=True: value==good → max_pts, value==bad → 0.
    """
    if bad == good:
        return max_pts if value <= good else 0
    ratio = (value - good) / (bad - good)
    ratio = max(0.0, min(1.0, ratio))
    pts = max_pts * (1 - ratio) if invert else max_pts * ratio
    return round(pts)


def _mean_absolute_deviation(samples: list[float]) -> float:
    if not samples:
        return 0.0
    mean = sum(samples) / len(samples)
    return sum(abs(x - mean) for x in samples) / len(samples)
