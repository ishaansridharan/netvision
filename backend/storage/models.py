"""
NetVision — SQLAlchemy ORM Models (storage/models.py)

Tables
──────
  packets   — recent captured packets (capped, oldest pruned)
  flows     — network flows (active + completed)
  alerts    — security / anomaly alerts
  stats_snapshots — periodic stats for time-series charts
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean, Column, Float, Integer, JSON, String, Text, DateTime
)
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

    # TCP
    tcp_flags   = Column(String)
    tcp_flags_raw = Column(Integer)
    tcp_seq     = Column(Integer)
    tcp_ack     = Column(Integer)
    tcp_window  = Column(Integer)

    # ICMP
    icmp_type   = Column(Integer)
    icmp_code   = Column(Integer)

    # ARP
    arp_op          = Column(String)
    arp_sender_mac  = Column(String)
    arp_sender_ip   = Column(String)
    arp_target_mac  = Column(String)
    arp_target_ip   = Column(String)

    # DNS
    dns_query_name  = Column(String)
    dns_query_type  = Column(String)
    dns_response_ips = Column(JSON)   # list[str]
    dns_is_response  = Column(Boolean)

    raw_summary = Column(Text)


class FlowORM(Base):
    __tablename__ = "flows"

    flow_id     = Column(String, primary_key=True)
    src_ip      = Column(String, index=True)
    dst_ip      = Column(String, index=True)
    src_port    = Column(Integer)
    dst_port    = Column(Integer)
    protocol    = Column(String)
    start_time  = Column(Float)
    last_seen   = Column(Float)
    fwd_packets = Column(Integer, default=0)
    bwd_packets = Column(Integer, default=0)
    fwd_bytes   = Column(Integer, default=0)
    bwd_bytes   = Column(Integer, default=0)
    tcp_state   = Column(String)


class AlertORM(Base):
    __tablename__ = "alerts"

    alert_id    = Column(String, primary_key=True)
    timestamp   = Column(Float, nullable=False, index=True)
    alert_type  = Column(String, index=True)
    severity    = Column(String)
    status      = Column(String, default="ACTIVE")
    source_ip   = Column(String)
    target_ip   = Column(String)
    description = Column(Text)
    evidence    = Column(JSON)


class StatsSnapshotORM(Base):
    __tablename__ = "stats_snapshots"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(Float, nullable=False, index=True)
    download_bps    = Column(Float)
    upload_bps      = Column(Float)
    packets_per_sec = Column(Float)
    latency_ms      = Column(Float)
    packet_loss_pct = Column(Float)
    jitter_ms       = Column(Float)
    active_connections = Column(Integer)
    health_score    = Column(Integer)
    total_packets   = Column(Integer)
    total_bytes     = Column(Integer)
    protocol_dist   = Column(JSON)
