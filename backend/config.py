"""
NetVision — Global configuration and tunable thresholds.

All detection thresholds, time windows, and system limits are
centralised here so both team members can adjust behaviour without
touching the detection/stats code.

Every value can be overridden through environment variables or a `.env`
file in the working directory (field name, upper-cased).

Components receive a Settings object at construction time instead of
reading the global singleton.  That is what lets the evaluation harness
run a static-threshold pipeline and an adaptive pipeline side by side on
the same traffic with different configurations.
"""

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


DetectionMode = Literal["static", "adaptive"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # ------------------------------------------------------------------ #
    # Application
    # ------------------------------------------------------------------ #
    app_title: str = "NetVision"
    app_version: str = "2.0.0"
    debug: bool = False

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    database_url: str = "sqlite:///./netvision.db"

    # Persisting every packet is expensive; off by default.  Alerts, flows
    # and stats snapshots are always persisted.
    persist_packets: bool = False

    # Maximum number of packet rows kept in the DB (oldest are pruned).
    max_packets_stored: int = 50_000

    # ------------------------------------------------------------------ #
    # Capture
    # ------------------------------------------------------------------ #
    # Packet buffer: how many parsed packets to keep in the in-memory
    # ring buffer that feeds the API.
    packet_ring_buffer_size: int = 2_000

    # Raw packets wait here between the sniffer thread and the analysis
    # worker.  When it is full, new packets are dropped and counted — this
    # is the "packet drop rate" reported by /metrics/pipeline.
    capture_queue_size: int = 20_000

    # Directory that /capture/replay may read pcap files from.  The API
    # only accepts bare file names inside it, never arbitrary paths.
    captures_dir: str = "captures"

    # ------------------------------------------------------------------ #
    # Statistics Engine
    # ------------------------------------------------------------------ #
    # Rolling window (seconds) for bandwidth / pps calculations.
    stats_rolling_window_s: float = 10.0

    # How often the pipeline emits a snapshot (seconds).
    stats_snapshot_interval_s: float = 1.0

    # Max stat-history snapshots kept in memory for /stats/history.
    stats_history_max: int = 3_600        # 1 hour at 1 snapshot/s

    # Window over which RTT samples are aggregated into latency/jitter.
    latency_window_s: float = 30.0

    # Minimum TCP data segments in the window before the retransmission
    # rate is trusted as a packet-loss estimate.
    loss_min_segments: int = 20

    # Comma-separated CIDRs treated as "local" for upload/download
    # classification.  Empty → derived from the capture interface, falling
    # back to RFC 1918 private ranges.
    local_networks: str = ""

    # Max hosts tracked by the host registry (oldest evicted first).
    max_tracked_hosts: int = 20_000

    # ------------------------------------------------------------------ #
    # Flow Tracker
    # ------------------------------------------------------------------ #
    # A flow is considered expired after this many seconds of inactivity.
    flow_idle_timeout_s: float = 60.0

    # Half-open TCP flows (SYN seen, handshake never completed) expire
    # faster — a SYN flood would otherwise fill the table.
    flow_half_open_timeout_s: float = 20.0

    # Closed / reset flows linger briefly so late packets still match.
    flow_closed_linger_s: float = 5.0

    # Hard cap on active flows; the least-recently-seen are evicted first.
    flow_max_active: int = 100_000

    # Completed flows kept in memory for the API.
    flow_max_completed: int = 5_000

    # ------------------------------------------------------------------ #
    # Detection — common
    # ------------------------------------------------------------------ #
    # "static": fixed thresholds (the baseline the report compares against)
    # "adaptive": EWMA baseline + z-score with flow context
    detection_mode: DetectionMode = "adaptive"

    # EWMA smoothing factor for adaptive baselines (per 1 s sample).
    baseline_alpha: float = 0.05

    # z-score above which a sample is anomalous.
    baseline_z_threshold: float = 3.0

    # Samples needed before a baseline is trusted.
    baseline_warmup_samples: int = 30

    # ------------------------------------------------------------------ #
    # Detection — Port Scan
    # ------------------------------------------------------------------ #
    # Sliding window in seconds for port-scan tracking.
    port_scan_window_s: float = 5.0

    # Static: distinct destination ports from one source within the window.
    port_scan_threshold: int = 15

    # Adaptive: the threshold never drops below this many ports.
    port_scan_adaptive_floor: int = 8

    # Seconds before the same source can raise another port-scan alert.
    port_scan_cooldown_s: float = 10.0

    # ------------------------------------------------------------------ #
    # Detection — SYN Flood
    # ------------------------------------------------------------------ #
    # Sliding window in seconds for SYN flood tracking.
    syn_flood_window_s: float = 10.0

    # Static: minimum SYN count within the window.
    syn_flood_syn_threshold: int = 200

    # Static: fraction of SYNs that must lack a completed handshake.
    syn_flood_incomplete_ratio: float = 0.80

    # Adaptive: SYN rate is measured over this short window (seconds).
    syn_flood_rate_window_s: float = 2.0

    # Adaptive: the SYN-rate threshold never drops below this (SYN/s).
    syn_flood_adaptive_floor_rate: float = 20.0

    # Adaptive: the half-open ratio threshold never drops below this.
    syn_flood_adaptive_min_ratio: float = 0.5

    # Seconds before the same target can raise another SYN-flood alert.
    syn_flood_cooldown_s: float = 30.0

    # ------------------------------------------------------------------ #
    # Detection — ARP
    # ------------------------------------------------------------------ #
    arp_cooldown_s: float = 60.0

    # Adaptive: a mapping change only counts as a conflict if the previous
    # MAC was still active within this many seconds.  A MAC that has been
    # silent longer than this is treated as a legitimate re-assignment.
    arp_conflict_window_s: float = 120.0

    # ------------------------------------------------------------------ #
    # Detection — Traffic Spike
    # ------------------------------------------------------------------ #
    # Static: alert when 1 s throughput exceeds this many bytes/sec.
    traffic_spike_static_bps: float = 1_250_000.0   # 10 Mbit/s

    # Adaptive: current rate must also be at least this multiple of the
    # baseline mean (guards against tiny-σ baselines).
    traffic_spike_multiplier: float = 3.0

    # Adaptive: ignore anything below this absolute rate (bytes/sec).  On a
    # quiet network μ + kσ can be tiny; a "spike" under 1 Mbit/s is not
    # operationally interesting whatever its z-score.
    traffic_spike_min_bps: float = 125_000.0   # 1 Mbit/s

    # Both modes: consecutive anomalous seconds before alerting.
    traffic_spike_min_duration_s: int = 2

    traffic_spike_cooldown_s: float = 30.0

    # ------------------------------------------------------------------ #
    # Network Health Score weights (renormalised over known components)
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

    # Alerts newer than this count against the threat component.
    health_alert_horizon_s: float = 300.0

    # Assumed interface capacity in Mbps (used for utilisation %).
    interface_capacity_mbps: float = 100.0


# Singleton — the live server's configuration.
settings = Settings()
