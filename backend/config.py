"""
NetVision — Global configuration and tunable thresholds.

All detection thresholds, time windows, and system limits are
centralised here so both team members can adjust behaviour without
touching the detection/stats code.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    app_title: str = "NetVision"
    app_version: str = "1.0.0"
    debug: bool = False

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    database_url: str = "sqlite:///./netvision.db"

    # Maximum number of packet rows kept in the DB (oldest are pruned).
    max_packets_stored: int = 50_000

    # ------------------------------------------------------------------ #
    # Capture
    # ------------------------------------------------------------------ #
    # Packet buffer: how many parsed packets to keep in the in-memory
    # ring buffer that feeds the API.
    packet_ring_buffer_size: int = 2_000

    # ------------------------------------------------------------------ #
    # Statistics Engine
    # ------------------------------------------------------------------ #
    # Rolling window (seconds) for bandwidth / pps calculations.
    stats_rolling_window_s: float = 10.0

    # How often the stats engine emits a snapshot (seconds).
    stats_snapshot_interval_s: float = 1.0

    # Max stat-history snapshots kept in memory for /stats/history.
    stats_history_max: int = 3_600        # 1 hour at 1 snapshot/s

    # ------------------------------------------------------------------ #
    # Flow Tracker
    # ------------------------------------------------------------------ #
    # A flow is considered expired after this many seconds of inactivity.
    flow_idle_timeout_s: float = 60.0

    # How often the flow GC runs (seconds).
    flow_gc_interval_s: float = 30.0

    # ------------------------------------------------------------------ #
    # Detection — Port Scan
    # ------------------------------------------------------------------ #
    # Minimum distinct destination ports from one source within the time
    # window to trigger a port-scan alert.
    port_scan_threshold: int = 15

    # Sliding window in seconds for port-scan tracking.
    port_scan_window_s: float = 5.0

    # ------------------------------------------------------------------ #
    # Detection — SYN Flood
    # ------------------------------------------------------------------ #
    # Minimum SYN count to consider a flood (within window).
    syn_flood_syn_threshold: int = 200

    # Fraction of SYNs that must lack a completed handshake.
    syn_flood_incomplete_ratio: float = 0.80

    # Sliding window in seconds for SYN flood tracking.
    syn_flood_window_s: float = 10.0

    # ------------------------------------------------------------------ #
    # Detection — Traffic Spike
    # ------------------------------------------------------------------ #
    # Spike multiplier: alert when current bandwidth > baseline * factor.
    traffic_spike_multiplier: float = 3.0

    # Exponential moving average alpha for baseline calculation.
    traffic_spike_ema_alpha: float = 0.05

    # Minimum baseline bytes/sec before spike detection is active
    # (avoids false positives at startup).
    traffic_spike_min_baseline: float = 10_000.0   # 10 KB/s

    # ------------------------------------------------------------------ #
    # Network Health Score weights (must sum to 1.0)
    # ------------------------------------------------------------------ #
    health_weight_latency: float = 0.25
    health_weight_packet_loss: float = 0.25
    health_weight_bandwidth: float = 0.25
    health_weight_threats: float = 0.25

    # Thresholds for health sub-scores
    health_latency_good_ms: float = 20.0
    health_latency_bad_ms: float = 150.0
    health_loss_good_pct: float = 0.5
    health_loss_bad_pct: float = 5.0
    health_bandwidth_good_pct: float = 50.0    # % of interface capacity
    health_bandwidth_bad_pct: float = 90.0

    # Assumed interface capacity in Mbps (used for utilisation %).
    interface_capacity_mbps: float = 100.0

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Singleton — import `settings` everywhere.
settings = Settings()
