"""
NetVision — Anomaly Detector Orchestrator (detection/detector.py)

This is the single entry point for all anomaly detection in NetVision.

Pipeline
────────
    PacketRecord → AnomalyDetector.process(pkt)
                        │
              ┌─────────┼───────────┬──────────────┐
              ▼         ▼           ▼              ▼
        PortScan   SynFlood    ArpAnomaly    (Spike via stats)
              │         │           │
              └─────────┼───────────┘
                        ▼
                   Alert (if any)
                        │
                   stored in _alerts deque
                   returned to caller

Usage
─────
    detector = AnomalyDetector()
    # In the stats engine's snapshot loop:
    spike_alert = detector.check_traffic_spike(current_bps, top_source)
    # In the packet callback:
    alert = detector.process(packet_record)
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Optional

from backend.detection.models import Alert
from backend.detection.port_scan import PortScanDetector
from backend.detection.syn_flood import SynFloodDetector
from backend.detection.arp_anomaly import ArpAnomalyDetector
from backend.detection.traffic_spike import TrafficSpikeDetector
from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)

_MAX_ALERTS = 10_000


class AnomalyDetector:
    """
    Orchestrates all detection rules and maintains the alert history.
    Thread-safe — process() is called from the capture thread,
    alert accessors from the API thread.
    """

    def __init__(self) -> None:
        self._port_scan    = PortScanDetector()
        self._syn_flood    = SynFloodDetector()
        self._arp_anomaly  = ArpAnomalyDetector()
        self._traffic_spike = TrafficSpikeDetector()

        self._alerts: deque[Alert] = deque(maxlen=_MAX_ALERTS)
        self._lock = threading.Lock()

        # Callbacks to notify when a new alert is generated (e.g. WebSocket)
        self._alert_callbacks: list = []

    # ------------------------------------------------------------------ #
    # Packet-driven detection (called per packet from capture thread)
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        """
        Run all packet-level detectors on *pkt*.
        Returns the first alert generated (if any) and stores it.
        Multiple detectors could fire on the same packet — we store all
        but return only the first to keep the callback signature simple.
        """
        alerts: list[Alert] = []

        for detector in (self._port_scan, self._syn_flood, self._arp_anomaly):
            try:
                alert = detector.process(pkt)
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                logger.debug("Detector %s error: %s", detector.__class__.__name__, exc)

        if alerts:
            with self._lock:
                for alert in alerts:
                    self._alerts.append(alert)
                    logger.warning(
                        "ALERT [%s] %s src=%s",
                        alert.alert_type, alert.description, alert.source_ip
                    )
            # Notify WebSocket callbacks
            for alert in alerts:
                self._notify(alert)
            return alerts[0]

        return None

    # ------------------------------------------------------------------ #
    # Stats-driven detection (called from StatsEngine snapshot loop)
    # ------------------------------------------------------------------ #

    def check_traffic_spike(
        self, current_bps: float, top_source_ip: Optional[str] = None
    ) -> Optional[Alert]:
        """
        Called once per stats snapshot with the current total bandwidth.
        """
        try:
            alert = self._traffic_spike.update_from_stats(current_bps, top_source_ip)
            if alert:
                with self._lock:
                    self._alerts.append(alert)
                logger.warning("ALERT [TRAFFIC_SPIKE] %s", alert.description)
                self._notify(alert)
                return alert
        except Exception as exc:
            logger.debug("TrafficSpike detector error: %s", exc)
        return None

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
        with self._lock:
            alerts = list(self._alerts)

        # Newest first
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        if severity:
            alerts = [a for a in alerts if a.severity == severity.upper()]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type.upper()]
        if status:
            alerts = [a for a in alerts if a.status == status.upper()]

        return alerts[:limit]

    def get_active_alert_count(self) -> int:
        with self._lock:
            return sum(1 for a in self._alerts if a.status == "ACTIVE")

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.status = "ACKNOWLEDGED"
                    return True
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.status = "RESOLVED"
                    return True
        return False

    # ------------------------------------------------------------------ #
    # ARP table accessor (for Network Map)
    # ------------------------------------------------------------------ #

    def get_arp_table(self) -> dict[str, str]:
        return self._arp_anomaly.get_arp_table()

    # ------------------------------------------------------------------ #
    # WebSocket notification callbacks
    # ------------------------------------------------------------------ #

    def add_alert_callback(self, cb) -> None:
        self._alert_callbacks.append(cb)

    def _notify(self, alert: Alert) -> None:
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass
