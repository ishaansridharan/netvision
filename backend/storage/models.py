"""
NetVision — SQLAlchemy ORM Models (storage/models.py)

Tables
──────
  packets          — captured packets (optional, capped, oldest pruned)
  flows            — completed network flows
  alerts           — security / anomaly alerts, with explanations
  stats_snapshots  — 1-second stats for time-series charts and reports
"""

from __future__ import annotations

from sqlalchemy import Column, Float, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class PacketORM(Base):
    __tablename__ = "packets"

    id          = Column(String, primary_key=True)
    timestamp   = Column(Float, nullable=False, index=True)
    src_mac     = Column(String)
    dst_mac     = Column(String)
    src_ip      = Column(String, index=True)
    dst_ip      = Column(String, index=True)
    ttl         = Column(Integer)
    protocol    = Column(String, index=True)
    src_port    = Column(Integer)
    dst_port    = Column(Integer)
    size        = Column(Integer)
    tcp_flags   = Column(String)
    icmp_type   = Column(Integer)
    arp_op      = Column(String)
    dns_query_name = Column(String)
    raw_summary = Column(Text)


class FlowORM(Base):
    __tablename__ = "flows"

    flow_id     = Column(String, primary_key=True)
    src_ip      = Column(String, index=True)
    dst_ip      = Column(String, index=True)
    src_port    = Column(Integer)
    dst_port    = Column(Integer)
    protocol    = Column(String)
    transport   = Column(String)
    start_time  = Column(Float, index=True)
    last_seen   = Column(Float)
    fwd_packets = Column(Integer, default=0)
    bwd_packets = Column(Integer, default=0)
    fwd_bytes   = Column(Integer, default=0)
    bwd_bytes   = Column(Integer, default=0)
    tcp_state   = Column(String)
    handshake_rtt_ms = Column(Float)
    retransmissions  = Column(Integer, default=0)


class AlertORM(Base):
    __tablename__ = "alerts"

    alert_id    = Column(String, primary_key=True)
    timestamp   = Column(Float, nullable=False, index=True)
    alert_type  = Column(String, index=True)
    severity    = Column(String)
    status      = Column(String, default="ACTIVE")
    mode        = Column(String)
    source_ip   = Column(String)
    target_ip   = Column(String)
    description = Column(Text)
    evidence    = Column(JSON)
    explanation = Column(JSON)


class StatsSnapshotORM(Base):
    __tablename__ = "stats_snapshots"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(Float, nullable=False, index=True)
    download_bps    = Column(Float)
    upload_bps      = Column(Float)
    lan_bps         = Column(Float)
    packets_per_sec = Column(Float)
    latency_ms      = Column(Float)
    jitter_ms       = Column(Float)
    packet_loss_pct = Column(Float)
    active_connections = Column(Integer)
    half_open_connections = Column(Integer)
    health_score    = Column(Integer)
    interval_packets = Column(Integer)
    interval_bytes  = Column(Integer)
    protocol_dist   = Column(JSON)
    top_talkers     = Column(JSON)
    top_destinations = Column(JSON)
    health_issues   = Column(JSON)
