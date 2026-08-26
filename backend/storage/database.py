"""
NetVision — Database Setup (storage/database.py)

Provides:
  • Engine / session factory
  • init_db() — create all tables on startup
  • Async-safe write helpers that run in a background thread so DB
    writes don't block the capture or API threads.
"""

from __future__ import annotations

import logging
import threading
import queue
import time
from contextlib import contextmanager
from typing import Callable

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session

from backend.config import settings
from backend.storage.models import Base, PacketORM, FlowORM, AlertORM, StatsSnapshotORM

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
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@contextmanager
def get_session() -> Session:
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
    """Create all tables if they don't exist yet."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialised at %s", settings.database_url)


# ──────────────────────────────────────────────────────────────────────────
# Async write queue — DB writes happen off the hot path
# ──────────────────────────────────────────────────────────────────────────

class DatabaseWriter:
    """
    Background thread that drains a write queue into SQLite.

    The capture thread enqueues write functions; this thread executes them
    in batches so the capture loop is never blocked by disk I/O.
    """

    _BATCH_SIZE = 50
    _FLUSH_INTERVAL = 2.0  # seconds

    def __init__(self) -> None:
        self._q: queue.Queue[Callable] = queue.Queue(maxsize=10_000)
        self._thread = threading.Thread(
            target=self._run, name="netvision-db-writer", daemon=True
        )
        self._running = False

    def start(self) -> None:
        self._running = True
        self._thread.start()
        logger.info("DatabaseWriter started.")

    def stop(self) -> None:
        self._running = False

    def enqueue(self, fn: Callable) -> None:
        """
        Enqueue a zero-argument callable that will be called inside a
        DB session on the writer thread.  Drops silently if the queue is full.
        """
        try:
            self._q.put_nowait(fn)
        except queue.Full:
            pass  # Prefer dropping over blocking the capture thread

    def _run(self) -> None:
        while self._running:
            batch: list[Callable] = []
            try:
                # Block for up to flush_interval waiting for the first item
                fn = self._q.get(timeout=self._FLUSH_INTERVAL)
                batch.append(fn)
            except queue.Empty:
                continue

            # Drain up to batch_size more without blocking
            while len(batch) < self._BATCH_SIZE:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break

            # Execute the whole batch in one transaction
            if batch:
                self._execute_batch(batch)

    def _execute_batch(self, batch: list[Callable]) -> None:
        try:
            with get_session() as session:
                for fn in batch:
                    try:
                        fn(session)
                    except Exception as exc:
                        logger.debug("DB write fn error: %s", exc)
        except Exception as exc:
            logger.error("DB batch write error: %s", exc)


# ──────────────────────────────────────────────────────────────────────────
# Convenience write helpers
# ──────────────────────────────────────────────────────────────────────────

def _persist_packet(pkt_dict: dict) -> Callable:
    """Returns a session-function that inserts or ignores a packet row."""
    def _fn(session: Session):
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        stmt = sqlite_insert(PacketORM).prefix_with("OR IGNORE").values(**pkt_dict)
        session.execute(stmt)
    return _fn


def _persist_flow(flow_dict: dict) -> Callable:
    """Upsert a flow row."""
    def _fn(session: Session):
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        stmt = (
            sqlite_insert(FlowORM)
            .prefix_with("OR REPLACE")
            .values(**flow_dict)
        )
        session.execute(stmt)
    return _fn


def _persist_alert(alert_dict: dict) -> Callable:
    def _fn(session: Session):
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        stmt = sqlite_insert(AlertORM).prefix_with("OR IGNORE").values(**alert_dict)
        session.execute(stmt)
    return _fn


def _persist_stats(stats_dict: dict) -> Callable:
    def _fn(session: Session):
        session.add(StatsSnapshotORM(**stats_dict))
    return _fn


def prune_old_packets(max_rows: int) -> None:
    """
    Keep only the newest max_rows packets.
    Called periodically (e.g. every 5 minutes) to cap DB size.
    """
    with get_session() as session:
        count = session.query(PacketORM).count()
        if count > max_rows:
            excess = count - max_rows
            subq = (
                session.query(PacketORM.id)
                .order_by(PacketORM.timestamp.asc())
                .limit(excess)
                .subquery()
            )
            session.query(PacketORM).filter(PacketORM.id.in_(subq)).delete(
                synchronize_session=False
            )
            logger.info("Pruned %d old packets from DB.", excess)
