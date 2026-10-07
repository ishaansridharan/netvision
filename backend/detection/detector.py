"""
NetVision — Anomaly Detector Orchestrator (detection/detector.py)

This is the single entry point for all anomaly detection in NetVision.

Pipeline
────────
    per packet:  (PacketRecord, FlowEvent) ─▶ PortScan, SynFlood, ArpAnomaly
    per tick:    StatsSnapshot             ─▶ TrafficSpike
                                              + baseline learning for all

                                   ▼
                        Alert(s) → history (with seq numbers) → callbacks
                                                                (WebSocket, DB)

Detection mode
──────────────
`mode` is "static" or "adaptive" and can be switched at runtime.  Baselines
keep learning in both modes, so switching to adaptive is immediate rather
than starting a fresh warm-up.

Usage
─────
    detector = AnomalyDetector(cfg, mode="adaptive")
    alerts = detector.process(packet_record, flow_event)
    alerts = detector.tick(now, snapshot)
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Callable, Optional

from backend.analyzer.flow_tracker import FlowEvent
from backend.config import Settings, settings as default_settings
from backend.detection.arp_anomaly import ArpAnomalyDetector
from backend.detection.models import Alert
from backend.detection.port_scan import PortScanDetector
from backend.detection.syn_flood import SynFloodDetector
from backend.detection.traffic_spike import TrafficSpikeDetector
from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)

_MAX_ALERTS = 10_000
_MODES = ("static", "adaptive")


class AnomalyDetector:
    """
    Orchestrates all detection rules and maintains the alert history.
    process()/tick() run on the analysis worker; accessors are called from
    API threads, so the history is guarded by a lock.
    """

    def __init__(self, cfg: Settings = default_settings, mode: Optional[str] = None) -> None:
        self._cfg = cfg
        mode = mode or cfg.detection_mode
        self._port_scan = PortScanDetector(cfg, mode)
        self._syn_flood = SynFloodDetector(cfg, mode)
        self._arp_anomaly = ArpAnomalyDetector(cfg, mode)
        self._traffic_spike = TrafficSpikeDetector(cfg, mode)
        self._mode = mode

        self._alerts: deque[Alert] = deque(maxlen=_MAX_ALERTS)
        self._lock = threading.Lock()
        self._alert_callbacks: list[Callable[[Alert], None]] = []

        self.counts_by_type: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    # Mode
    # ------------------------------------------------------------------ #

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        if mode not in _MODES:
            raise ValueError(f"mode must be one of {_MODES}")
        self._mode = mode
        for d in (self._port_scan, self._syn_flood, self._arp_anomaly, self._traffic_spike):
            d.mode = mode
        logger.info("Detection mode set to %s", mode)

    def set_gateway(self, gateway_ip: Optional[str]) -> None:
        self._arp_anomaly.gateway_ip = gateway_ip

    def seed_arp(self, table: dict[str, str]) -> None:
        self._arp_anomaly.seed(table)

    # ------------------------------------------------------------------ #
    # Packet-driven detection
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord, event: Optional[FlowEvent] = None) -> list[Alert]:
        """Run all packet-level detectors on *pkt*; return any new alerts."""
        alerts: list[Alert] = []
        for detector in (self._port_scan, self._syn_flood, self._arp_anomaly):
            try:
                alert = detector.process(pkt, event)
            except Exception as exc:
                logger.exception("Detector %s error: %s", detector.__class__.__name__, exc)
                continue
            if alert:
                alerts.append(alert)
        if alerts:
            self._record(alerts)
        return alerts

    # ------------------------------------------------------------------ #
    # Tick-driven detection + baseline learning
    # ------------------------------------------------------------------ #

    def tick(self, now: float, snapshot=None) -> list[Alert]:
        """Learn baselines and run tick-level rules.  snapshot=None means
        "not observing": the throughput baseline is left untouched."""
        alerts: list[Alert] = []
        for d in (self._port_scan, self._syn_flood, self._arp_anomaly):
            try:
                d.tick(now)
            except Exception as exc:
                logger.exception("Detector %s tick error: %s", d.__class__.__name__, exc)
        if snapshot is None:
            self._traffic_spike.pause()
        else:
            try:
                alert = self._traffic_spike.check(
                    now, snapshot.instant_bps, snapshot.top_talkers
                )
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                logger.exception("TrafficSpike detector error: %s", exc)
        if alerts:
            self._record(alerts)
        return alerts

    def _record(self, alerts: list[Alert]) -> None:
        with self._lock:
            for alert in alerts:
                self._alerts.append(alert)
                self.counts_by_type[alert.alert_type] = (
                    self.counts_by_type.get(alert.alert_type, 0) + 1
                )
        for alert in alerts:
            logger.warning(
                "ALERT [%s/%s] %s", alert.alert_type, alert.mode, alert.description
            )
            self._notify(alert)

    # ------------------------------------------------------------------ #
    # Alert accessors
    # ------------------------------------------------------------------ #

    def get_alerts(
        self,
        limit: int = 200,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[Alert]:
        """Newest first, optionally filtered."""
        with self._lock:
            alerts = list(self._alerts)
        alerts.reverse()   # deque is already in seq order

        if severity:
            alerts = [a for a in alerts if a.severity == severity.upper()]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type.upper()]
        if status:
            alerts = [a for a in alerts if a.status == status.upper()]

        return alerts[:limit]

    def get_alerts_since(self, seq: int, limit: int = 100) -> list[Alert]:
        """Alerts with seq > *seq*, oldest first (for streaming cursors)."""
        out: list[Alert] = []
        with self._lock:
            for alert in reversed(self._alerts):
                if alert.seq <= seq:
                    break
                out.append(alert)
        out.reverse()
        return out[-limit:]

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    return alert
        return None

    def latest_seq(self) -> int:
        with self._lock:
            return self._alerts[-1].seq if self._alerts else 0

    def recent_unresolved(self, now: float, horizon_s: float) -> list[Alert]:
        """Unresolved alerts from the last *horizon_s* seconds (health score)."""
        cutoff = now - horizon_s
        out: list[Alert] = []
        with self._lock:
            for alert in reversed(self._alerts):
                if alert.timestamp < cutoff:
                    break
                if alert.status != "RESOLVED":
                    out.append(alert)
        return out

    def get_active_alert_count(self) -> int:
        with self._lock:
            return sum(1 for a in self._alerts if a.status == "ACTIVE")

    def set_status(self, alert_id: str, status: str) -> Optional[Alert]:
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.status = status
                    return alert
        return None

    def acknowledge_alert(self, alert_id: str) -> bool:
        return self.set_status(alert_id, "ACKNOWLEDGED") is not None

    def resolve_alert(self, alert_id: str) -> bool:
        return self.set_status(alert_id, "RESOLVED") is not None

    def load_history(self, alerts: list[Alert]) -> None:
        """Restore persisted alerts at startup (oldest first)."""
        with self._lock:
            for alert in alerts:
                self._alerts.append(alert)

    # ------------------------------------------------------------------ #
    # Introspection (Security view, /detection endpoints)
    # ------------------------------------------------------------------ #

    def get_arp_table(self) -> dict[str, str]:
        return self._arp_anomaly.get_arp_table()

    def get_arp_rebindings(self) -> list[dict]:
        return list(self._arp_anomaly.rebindings)

    def baseline_summary(self) -> dict:
        return {
            "mode": self._mode,
            "port_scan": self._port_scan.baseline_summary(),
            "syn_flood": self._syn_flood.baseline_summary(),
            "traffic_spike": self._traffic_spike.baseline_summary(),
        }

    # ------------------------------------------------------------------ #
    # Notification callbacks
    # ------------------------------------------------------------------ #

    def add_alert_callback(self, cb: Callable[[Alert], None]) -> None:
        self._alert_callbacks.append(cb)

    def _notify(self, alert: Alert) -> None:
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception as exc:
                logger.debug("Alert callback error: %s", exc)
