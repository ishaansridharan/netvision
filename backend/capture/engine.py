"""
NetVision — Packet Capture Engine (capture/engine.py)

Runs Scapy's sniff() in a background daemon thread.
Every captured packet is:
  1. Parsed into a PacketRecord by the parser module
  2. Pushed into a thread-safe deque (ring buffer) for the API
  3. Forwarded to all registered callbacks (flow tracker, stats engine, detector)

Usage
─────
    engine = CaptureEngine()
    engine.add_callback(my_handler)
    engine.start("Wi-Fi")
    ...
    engine.stop()
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable

from backend.config import settings
from backend.parser.packet_parser import PacketRecord, parse_packet

logger = logging.getLogger(__name__)

# Type alias for pipeline callbacks
PacketCallback = Callable[[PacketRecord], None]


class CaptureEngine:
    """
    Thread-safe packet capture engine.

    The capture loop runs in a daemon thread so it dies automatically when
    the main process exits.  All analysis callbacks are invoked synchronously
    inside that thread — keep them fast.
    """

    def __init__(self) -> None:
        self._interface: str | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running = False

        # Ring buffer — newest packet at right, oldest auto-dropped from left
        self._ring: deque[PacketRecord] = deque(
            maxlen=settings.packet_ring_buffer_size
        )
        self._ring_lock = threading.Lock()

        # Registered pipeline callbacks
        self._callbacks: list[PacketCallback] = []
        self._cb_lock = threading.Lock()

        # Counters (volatile — read without a lock for speed)
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: float | None = None

    # ------------------------------------------------------------------ #
    # Public control API
    # ------------------------------------------------------------------ #

    def add_callback(self, cb: PacketCallback) -> None:
        """Register a function to be called for every captured packet."""
        with self._cb_lock:
            self._callbacks.append(cb)

    def start(self, interface: str) -> None:
        """Start capturing on *interface*. Raises RuntimeError if already running."""
        if self._running:
            raise RuntimeError(
                f"Capture already running on '{self._interface}'. Call stop() first."
            )

        self._interface = interface
        self._stop_event.clear()
        self._running = True
        self.start_time = time.time()

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="netvision-capture",
            daemon=True,
        )
        self._thread.start()
        logger.info("Capture started on interface '%s'", interface)

    def stop(self) -> None:
        """Signal the capture loop to stop and wait for the thread to finish."""
        if not self._running:
            return

        self._stop_event.set()
        self._running = False

        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

        logger.info("Capture stopped.")

    # ------------------------------------------------------------------ #
    # State accessors (thread-safe)
    # ------------------------------------------------------------------ #

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def interface(self) -> str | None:
        return self._interface

    def get_recent_packets(self, limit: int | None = None) -> list[PacketRecord]:
        """Return up to *limit* most-recent packets from the ring buffer."""
        with self._ring_lock:
            packets = list(self._ring)
        if limit:
            return packets[-limit:]
        return packets

    def get_status(self) -> dict:
        uptime = (time.time() - self.start_time) if self.start_time else 0.0
        return {
            "running": self._running,
            "interface": self._interface,
            "uptime_seconds": round(uptime, 1),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
        }

    # ------------------------------------------------------------------ #
    # Internal capture loop
    # ------------------------------------------------------------------ #

    def _capture_loop(self) -> None:
        """Main loop: called inside the daemon thread."""
        # Import Scapy lazily — avoids import-time Npcap requirement
        try:
            from scapy.all import sniff  # type: ignore[import]
        except ImportError as exc:
            logger.error("Scapy not installed: %s", exc)
            self._running = False
            return

        logger.debug("Scapy sniff() starting on '%s'", self._interface)

        try:
            sniff(
                iface=self._interface,
                prn=self._handle_packet,
                store=False,           # Don't accumulate in Scapy's buffer
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
            logger.error("Capture error on '%s': %s", self._interface, exc)
        finally:
            self._running = False
            logger.debug("Capture loop exited.")

    def _handle_packet(self, raw_pkt) -> None:
        """Called by Scapy for every captured packet (in the capture thread)."""
        try:
            record = parse_packet(raw_pkt)
        except Exception as exc:
            logger.debug("Parser error: %s", exc)
            return

        if record is None:
            return

        # Update counters
        self.total_packets += 1
        self.total_bytes += record.size

        # Push to ring buffer
        with self._ring_lock:
            self._ring.append(record)

        # Dispatch to all registered callbacks
        with self._cb_lock:
            callbacks = list(self._callbacks)

        for cb in callbacks:
            try:
                cb(record)
            except Exception as exc:
                logger.debug("Callback %s error: %s", cb, exc)
