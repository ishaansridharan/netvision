"""
NetVision — Database Setup (storage/database.py)

Provides:
  • Engine / session factory
  • init_db() — create tables and add any columns missing from an older DB
  • DatabaseWriter — background thread so DB writes never block analysis
  • persist_* helpers — build write functions for the writer queue
  • query helpers for the Reports view and alert history
"""

from __future__ import annotations

import logging
import queue
import threading
from contextlib import contextmanager
from typing import Callable, Optional

from sqlalchemy import create_engine, event, func, inspect, text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from backend.config import settings
from backend.storage.models import AlertORM, Base, FlowORM, PacketORM, StatsSnapshotORM

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# Engine & session factory
# ──────────────────────────────────────────────────────────────────────────

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},  # SQLite + multi-thread
    echo=False,
)


# Enable WAL mode for SQLite — allows concurrent readers + 1 writer
@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@contextmanager
def get_session():
    """Context manager that yields a DB session and handles commit/rollback."""
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create all tables, then add columns that an older database lacks."""
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
    logger.info("Database initialised at %s", settings.database_url)


def _add_missing_columns() -> None:
    """
    Minimal additive migration: create_all() never alters existing tables,
    so a database from an earlier version would be missing new columns.
    Every model column is nullable, so ADD COLUMN is always safe.
    """
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                coltype = col.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {coltype}'))
                logger.info("Migrated: added %s.%s", table.name, col.name)


# ──────────────────────────────────────────────────────────────────────────
# Async write queue — DB writes happen off the hot path
# ──────────────────────────────────────────────────────────────────────────

class DatabaseWriter:
    """
    Background thread that drains a write queue into SQLite.

    The analysis worker enqueues write functions; this thread executes them
    in batches so analysis is never blocked by disk I/O.
    """

    _BATCH_SIZE = 200
    _FLUSH_INTERVAL = 1.0  # seconds

    def __init__(self) -> None:
        self._q: queue.Queue[Callable[[Session], None]] = queue.Queue(maxsize=20_000)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.dropped = 0
        self.written = 0

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name="netvision-db-writer", daemon=True)
        self._thread.start()
        logger.info("DatabaseWriter started.")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._flush_remaining()

    def enqueue(self, fn: Callable[[Session], None]) -> None:
        """
        Enqueue a callable taking a Session, run on the writer thread.
        Drops (and counts) if the queue is full rather than blocking analysis.
        """
        try:
            self._q.put_nowait(fn)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while self._running:
            batch: list[Callable] = []
            try:
                batch.append(self._q.get(timeout=self._FLUSH_INTERVAL))
            except queue.Empty:
                continue
            while len(batch) < self._BATCH_SIZE:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            self._execute_batch(batch)

    def _flush_remaining(self) -> None:
        batch: list[Callable] = []
        while True:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        if batch:
            self._execute_batch(batch)

    def _execute_batch(self, batch: list[Callable]) -> None:
        try:
            with get_session() as session:
                for fn in batch:
                    try:
                        fn(session)
                        self.written += 1
                    except Exception as exc:
                        logger.debug("DB write fn error: %s", exc)
        except Exception as exc:
            logger.error("DB batch write error: %s", exc)


# ──────────────────────────────────────────────────────────────────────────
# Write helpers (each returns a function for DatabaseWriter.enqueue)
# ──────────────────────────────────────────────────────────────────────────

_PACKET_COLS = {c.name for c in PacketORM.__table__.columns}
_FLOW_COLS = {c.name for c in FlowORM.__table__.columns}
_ALERT_COLS = {c.name for c in AlertORM.__table__.columns}


def persist_packet(pkt_dict: dict) -> Callable[[Session], None]:
    row = {k: v for k, v in pkt_dict.items() if k in _PACKET_COLS}

    def _fn(session: Session):
        session.execute(sqlite_insert(PacketORM).prefix_with("OR IGNORE").values(**row))
    return _fn


def persist_flow(flow) -> Callable[[Session], None]:
    row = {k: v for k, v in flow.to_dict().items() if k in _FLOW_COLS}

    def _fn(session: Session):
        session.execute(sqlite_insert(FlowORM).prefix_with("OR REPLACE").values(**row))
    return _fn


def persist_alert(alert) -> Callable[[Session], None]:
    row = {k: v for k, v in alert.to_dict().items() if k in _ALERT_COLS}

    def _fn(session: Session):
        session.execute(sqlite_insert(AlertORM).prefix_with("OR REPLACE").values(**row))
    return _fn


def persist_snapshot(snap) -> Callable[[Session], None]:
    row = dict(
        timestamp=snap.timestamp,
        download_bps=snap.download_bps,
        upload_bps=snap.upload_bps,
        lan_bps=snap.lan_bps,
        packets_per_sec=snap.packets_per_sec,
        latency_ms=snap.latency_ms,
        jitter_ms=snap.jitter_ms,
        packet_loss_pct=snap.packet_loss_pct,
        active_connections=snap.active_connections,
        half_open_connections=snap.half_open_connections,
        health_score=snap.health_score,
        interval_packets=snap.interval_packets,
        interval_bytes=snap.interval_bytes,
        protocol_dist=snap.protocol_dist,
        top_talkers=snap.top_talkers[:5],
        top_destinations=snap.top_destinations[:5],
        health_issues=[
            {"name": c["name"], "points_lost": c["points_lost"], "reason": c["reason"],
             "culprit": c.get("culprit")}
            for c in snap.health.get("components", [])
            if c.get("points_lost", 0) >= 1
        ],
    )

    def _fn(session: Session):
        session.add(StatsSnapshotORM(**row))
    return _fn


def persist_alert_status(alert_id: str, status: str) -> Callable[[Session], None]:
    def _fn(session: Session):
        session.query(AlertORM).filter(AlertORM.alert_id == alert_id).update({"status": status})
    return _fn


# ──────────────────────────────────────────────────────────────────────────
# Read helpers
# ──────────────────────────────────────────────────────────────────────────

def load_recent_alerts(limit: int = 1_000) -> list[dict]:
    """Most recent persisted alerts, oldest first."""
    with get_session() as session:
        rows = (
            session.query(AlertORM)
            .order_by(AlertORM.timestamp.desc())
            .limit(limit)
            .all()
        )
        out = [
            {c: getattr(r, c) for c in _ALERT_COLS} for r in rows
        ]
    out.reverse()
    return out


def snapshots_between(start: float, end: float) -> list[StatsSnapshotORM]:
    with get_session() as session:
        rows = (
            session.query(StatsSnapshotORM)
            .filter(StatsSnapshotORM.timestamp >= start, StatsSnapshotORM.timestamp <= end)
            .order_by(StatsSnapshotORM.timestamp.asc())
            .all()
        )
        session.expunge_all()
        return rows


def alerts_between(start: float, end: float) -> list[dict]:
    with get_session() as session:
        rows = (
            session.query(AlertORM)
            .filter(AlertORM.timestamp >= start, AlertORM.timestamp <= end)
            .order_by(AlertORM.timestamp.asc())
            .all()
        )
        return [{c: getattr(r, c) for c in _ALERT_COLS} for r in rows]


def flow_totals_between(start: float, end: float, limit: int = 10) -> dict:
    """Top destination ports and completed-flow count for a time range."""
    with get_session() as session:
        total = (
            session.query(func.count(FlowORM.flow_id))
            .filter(FlowORM.start_time >= start, FlowORM.start_time <= end)
            .scalar()
        )
        ports = (
            session.query(
                FlowORM.dst_port, FlowORM.transport,
                func.count(FlowORM.flow_id),
                func.sum(FlowORM.fwd_bytes + FlowORM.bwd_bytes),
            )
            .filter(FlowORM.start_time >= start, FlowORM.start_time <= end)
            .group_by(FlowORM.dst_port, FlowORM.transport)
            .order_by(func.sum(FlowORM.fwd_bytes + FlowORM.bwd_bytes).desc())
            .limit(limit)
            .all()
        )
    return {
        "completed_flows": total or 0,
        "top_services": [
            {"port": p, "transport": t, "flows": n, "bytes": int(b or 0)}
            for p, t, n, b in ports
        ],
    }


def prune(max_packets: int, snapshot_retention_s: float, now: float) -> None:
    """Cap the packet table and drop stats older than the retention window."""
    with get_session() as session:
        count = session.query(func.count(PacketORM.id)).scalar() or 0
        if count > max_packets:
            cutoff_row = (
                session.query(PacketORM.timestamp)
                .order_by(PacketORM.timestamp.desc())
                .offset(max_packets)
                .limit(1)
                .scalar()
            )
            if cutoff_row is not None:
                session.query(PacketORM).filter(PacketORM.timestamp <= cutoff_row).delete(
                    synchronize_session=False
                )
        session.query(StatsSnapshotORM).filter(
            StatsSnapshotORM.timestamp < now - snapshot_retention_s
        ).delete(synchronize_session=False)
