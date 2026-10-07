"""
NetVision — Analysis Pipeline (pipeline.py)

One object that wires the analysis stages together:

    PacketRecord ─▶ HostRegistry ─▶ FlowTracker ─▶ StatsEngine ─▶ AnomalyDetector
                                        │ FlowEvent      │ (packet stats)  │ (scan / flood / ARP)
                                        └────────────────┴─────────────────┘
    tick(now)    ─▶ flow expiry ─▶ StatsSnapshot ─▶ spike detection + baseline learning

The same class is used by:
  • the live server  — CaptureEngine's worker calls process() per packet and
                       tick(time.time()) once per interval;
  • the evaluation   — run_offline() replays a packet list and ticks on
                       packet time, so results are deterministic;
  • the tests.

The pipeline itself has no threads and no I/O.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from backend.analyzer.flow_tracker import FlowTracker
from backend.analyzer.hosts import HostRegistry
from backend.analyzer.stats_engine import StatsEngine, StatsSnapshot
from backend.config import Settings, settings as default_settings
from backend.detection.detector import AnomalyDetector
from backend.detection.models import Alert
from backend.parser.packet_parser import PacketRecord


class Pipeline:
    def __init__(self, cfg: Settings = default_settings, mode: Optional[str] = None) -> None:
        self.cfg = cfg
        self.hosts = HostRegistry(cfg.max_tracked_hosts, cfg.local_networks)
        self.flows = FlowTracker(cfg)
        self.detector = AnomalyDetector(cfg, mode)
        self.stats = StatsEngine(
            cfg, self.hosts, self.flows, recent_alerts_fn=self.detector.recent_unresolved
        )
        self.packets_processed = 0

    def process(self, pkt: PacketRecord) -> list[Alert]:
        self.packets_processed += 1
        self.hosts.observe(pkt)
        event = self.flows.process(pkt)
        self.stats.process(pkt, event)
        return self.detector.process(pkt, event)

    def tick(self, now: float, observing: bool = True) -> tuple[StatsSnapshot, list[Alert]]:
        """
        *observing* is False while no capture source is running: stats still
        tick (the dashboard shows zeros), but baselines must not learn that
        an unobserved network is "silent" — otherwise ordinary traffic
        resuming after an idle period would look like a spike.
        """
        self.flows.tick(now)
        snap = self.stats.tick(now)
        alerts = self.detector.tick(now, snap if observing else None)
        return snap, alerts

    def run_offline(
        self,
        packets: Iterable[PacketRecord],
        on_alert: Optional[Callable[[Alert], None]] = None,
        tail_s: float = 5.0,
    ) -> list[Alert]:
        """
        Replay *packets* (in timestamp order) ticking on packet time.
        Returns all alerts.  *tail_s* extra seconds of ticks run after the
        last packet so time-driven detectors can finish.
        """
        interval = self.cfg.stats_snapshot_interval_s
        alerts: list[Alert] = []
        next_tick: Optional[float] = None
        last_ts: Optional[float] = None

        def emit(batch: list[Alert]) -> None:
            alerts.extend(batch)
            if on_alert:
                for a in batch:
                    on_alert(a)

        for pkt in packets:
            ts = pkt.timestamp
            if next_tick is None:
                next_tick = float(int(ts)) + interval
            while ts >= next_tick:
                emit(self.tick(next_tick)[1])
                next_tick += interval
            emit(self.process(pkt))
            last_ts = ts

        if last_ts is not None and next_tick is not None:
            end = last_ts + tail_s
            while next_tick <= end:
                emit(self.tick(next_tick)[1])
                next_tick += interval
        return alerts
