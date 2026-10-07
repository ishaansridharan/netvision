"""
NetVision — Shared Application State (api/state.py)

This module owns the single instances of all major engine components.
All API routes and the WebSocket handler import from here.

Separation of concerns
───────────────────────
• Instantiation happens here, not in main.py, so routes can import
  state without circular imports.
• main.py calls the lifecycle methods (start / stop).
• The analysis itself lives in backend.pipeline.Pipeline, which has no
  threads or I/O; this module connects it to capture and storage.
"""

from __future__ import annotations

import logging

from backend.capture.engine import CaptureEngine
from backend.capture.interface import (
    default_gateway, interface_addressing, read_os_arp_cache,
)
from backend.config import settings
from backend.pipeline import Pipeline
from backend.storage.database import (
    DatabaseWriter, persist_alert, persist_flow, persist_packet, persist_snapshot,
)

logger = logging.getLogger(__name__)

# ── Singleton instances ──────────────────────────────────────────────── #

pipeline       = Pipeline(settings)
capture_engine = CaptureEngine(settings)
db_writer      = DatabaseWriter()

# Convenience aliases used throughout the routes
flow_tracker     = pipeline.flows
stats_engine     = pipeline.stats
anomaly_detector = pipeline.detector
host_registry    = pipeline.hosts


# ── Wire the pipeline ────────────────────────────────────────────────── #
# Every parsed packet and every tick run on the capture engine's single
# analysis worker thread.

def _on_packet(pkt) -> None:
    pipeline.process(pkt)
    if settings.persist_packets:
        db_writer.enqueue(persist_packet(pkt.to_dict()))


def _on_tick(now: float) -> None:
    # Baselines only learn while a capture source is actually running.
    snap, _ = pipeline.tick(now, observing=capture_engine.is_running)
    db_writer.enqueue(persist_snapshot(snap))


capture_engine.add_callback(_on_packet)
capture_engine.add_tick_callback(_on_tick)

anomaly_detector.add_alert_callback(lambda alert: db_writer.enqueue(persist_alert(alert)))
flow_tracker.add_close_callback(lambda flow: db_writer.enqueue(persist_flow(flow)))


def configure_for_interface(interface: str) -> dict:
    """
    Tell the pipeline which addresses are local, which host is the gateway,
    and seed the ARP detector from the OS cache.  Called on capture start.
    """
    ips, nets = interface_addressing(interface)
    gateway = default_gateway()
    host_registry.configure_interface(ips, nets, gateway)
    anomaly_detector.set_gateway(gateway)
    arp = read_os_arp_cache()
    anomaly_detector.seed_arp(arp)
    info = {"addresses": ips, "networks": nets, "gateway": gateway, "arp_seeded": len(arp)}
    logger.info("Interface %s configured: %s", interface, info)
    return info
