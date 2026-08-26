"""
NetVision — Shared Application State (api/state.py)

This module owns the single instances of all major engine components.
All API routes and the WebSocket handler import from here.

Separation of concerns
───────────────────────
• Instantiation happens here, not in main.py, so routes can import
  state without circular imports.
• main.py calls the lifecycle methods (start / stop).
"""

from __future__ import annotations

from backend.capture.engine import CaptureEngine
from backend.analyzer.flow_tracker import FlowTracker
from backend.analyzer.stats_engine import StatsEngine
from backend.detection.detector import AnomalyDetector
from backend.storage.database import DatabaseWriter

# ── Singleton instances ──────────────────────────────────────────────── #

capture_engine   = CaptureEngine()
flow_tracker     = FlowTracker()
anomaly_detector = AnomalyDetector()
db_writer        = DatabaseWriter()

stats_engine = StatsEngine(
    flow_tracker=flow_tracker,
    active_alert_count_fn=anomaly_detector.get_active_alert_count,
)

# ── Wire the pipeline ────────────────────────────────────────────────── #
# Each captured packet flows through the full pipeline in order:
#   CaptureEngine → FlowTracker → StatsEngine → AnomalyDetector

def _pipeline_callback(pkt):
    """Fan-out a parsed packet to all analysis components."""
    flow_tracker.process(pkt)
    stats_engine.process(pkt)
    anomaly_detector.process(pkt)

capture_engine.add_callback(_pipeline_callback)
