"""
NetVision — Packet Capture Engine (capture/engine.py)

Two stages joined by a bounded queue:

    ┌────────────────────┐  (bytes, ts,     ┌──────────────────────────────┐
    │ source thread      │   linktype)      │ analysis worker (1 thread)    │
    │  • live: raw L2    │ ───────────────▶ │  fast parse → ring buffer →   │
    │    socket reader   │  bounded queue   │  packet callbacks (pipeline)  │
    │  • replay: pcap    │  (drops counted) │  tick callbacks every 1 s     │
    └────────────────────┘                  └──────────────────────────────┘

Why split?
──────────
If analysis ran inside the capture callback, any slow moment would stall
capture and packets would be lost invisibly in the kernel.  Here the
source thread only enqueues raw bytes; if analysis falls behind, the queue
fills and drops are *counted* — the packet-drop-rate metric.

Why raw bytes?
──────────────
Scapy opens the capture socket (Npcap on Windows, AF_PACKET on Linux), but
frames are read with recv_raw() and decoded by parser.fast_parser — ~13 µs
per packet instead of ~210 µs for full Scapy dissection.

Single worker thread
────────────────────
Parsing, per-packet analysis and the periodic tick all run on the worker,
so the pipeline never sees concurrent mutation.

Sources
───────
  • start(interface, bpf_filter) — live capture (needs Npcap on Windows,
    root or CAP_NET_RAW on Linux)
  • start_replay(pcap_path, speed, loop) — replays a capture file at its
    original pace (×speed), re-stamping packets with the current time so
    the live dashboard behaves exactly as with real traffic.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import deque
from typing import Callable, Optional

from backend.capture.pcapfile import iter_raw
from backend.config import Settings, settings as default_settings
from backend.parser.fast_parser import linktype_of, parse_frame
from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)

PacketCallback = Callable[[PacketRecord], None]
TickCallback = Callable[[float], None]
RawFrame = tuple[bytes, float, int]   # (frame bytes, timestamp, pcap linktype)

_METRICS_HISTORY = 300
_SELECT_TIMEOUT_S = 0.2


class CaptureError(RuntimeError):
    """Capture could not be started; message is suitable for the user."""


class CaptureEngine:
    """Thread-safe capture source + analysis worker."""

    def __init__(self, cfg: Settings = default_settings) -> None:
        self._cfg = cfg
        self._q: queue.Queue[RawFrame] = queue.Queue(maxsize=cfg.capture_queue_size)

        # Ring buffer — newest packet at right, oldest auto-dropped from left
        self._ring: deque[PacketRecord] = deque(maxlen=cfg.packet_ring_buffer_size)
        self._ring_lock = threading.Lock()

        self._packet_callbacks: list[PacketCallback] = []
        self._tick_callbacks: list[TickCallback] = []

        # Source state
        self._source: Optional[str] = None          # "live" | "replay"
        self._interface: Optional[str] = None
        self._replay_path: Optional[str] = None
        self._source_thread: Optional[threading.Thread] = None
        self._source_stop = threading.Event()
        self._source_error: Optional[str] = None
        self.start_time: Optional[float] = None

        # Worker
        self._worker: Optional[threading.Thread] = None
        self._worker_stop = threading.Event()

        # Counters (each written by one thread; read without locks)
        self._seq = 0
        self.received = 0          # handed to us by the source
        self.dropped = 0           # queue full
        self.unparsed = 0          # not IPv4/ARP, or malformed
        self.processed = 0         # fully analysed
        self.total_bytes = 0
        self.max_queue_depth = 0
        self._proc_time_s = 0.0    # processing time since last tick
        self._proc_count = 0
        self._last_tick_processed = 0
        self._last_tick_received = 0
        self._last_tick_dropped = 0
        self._last_tick_time: Optional[float] = None
        self._metrics: dict = {}
        self._metrics_history: deque[dict] = deque(maxlen=_METRICS_HISTORY)

    # ------------------------------------------------------------------ #
    # Wiring
    # ------------------------------------------------------------------ #

    def add_callback(self, cb: PacketCallback) -> None:
        """Register a function to be called for every parsed packet."""
        self._packet_callbacks.append(cb)

    def add_tick_callback(self, cb: TickCallback) -> None:
        """Register a function called every `stats_snapshot_interval_s`."""
        self._tick_callbacks.append(cb)

    # ------------------------------------------------------------------ #
    # Worker lifecycle (runs for the life of the server)
    # ------------------------------------------------------------------ #

    def start_worker(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._worker_stop.clear()
        self._worker = threading.Thread(
            target=self._worker_loop, name="netvision-analysis", daemon=True
        )
        self._worker.start()

    def stop_worker(self) -> None:
        self._worker_stop.set()
        if self._worker:
            self._worker.join(timeout=5.0)
            self._worker = None

    # ------------------------------------------------------------------ #
    # Sources
    # ------------------------------------------------------------------ #

    def start(self, interface: str, bpf_filter: Optional[str] = None) -> None:
        """Start live capture on *interface*.  Raises CaptureError on failure."""
        if self.is_running:
            raise CaptureError(f"Capture already running ({self.describe_source()}). Stop it first.")
        try:
            from scapy.all import conf  # type: ignore[import]
        except ImportError as exc:
            raise CaptureError(f"Scapy is not installed: {exc}") from exc

        try:
            kwargs = {"iface": interface}
            if bpf_filter:
                kwargs["filter"] = bpf_filter
            sock = conf.L2listen(**kwargs)
        except Exception as exc:
            raise CaptureError(_explain_capture_error(exc, interface)) from exc

        self._begin("live", interface=interface)
        self._source_thread = threading.Thread(
            target=self._live_loop, args=(sock,), name="netvision-capture", daemon=True
        )
        self._source_thread.start()
        logger.info("Live capture started on '%s'%s", interface,
                    f" (filter: {bpf_filter})" if bpf_filter else "")

    def start_replay(self, path: str, speed: float = 1.0, loop: bool = False) -> None:
        """Replay a pcap file into the pipeline as if it were live traffic."""
        if self.is_running:
            raise CaptureError(f"Capture already running ({self.describe_source()}). Stop it first.")
        if not os.path.isfile(path):
            raise CaptureError(f"pcap file not found: {path}")

        self._begin("replay", replay_path=path)
        self._source_thread = threading.Thread(
            target=self._replay_loop, args=(path, speed, loop),
            name="netvision-replay", daemon=True,
        )
        self._source_thread.start()
        logger.info("Replaying %s at %.1fx%s", path, speed, " (looping)" if loop else "")

    def _begin(self, source: str, interface: Optional[str] = None,
               replay_path: Optional[str] = None) -> None:
        self._source_stop.clear()
        self._source = source
        self._interface = interface
        self._replay_path = replay_path
        self._source_error = None
        self.start_time = time.time()

    def stop(self) -> None:
        """Stop the current source.  The worker keeps running."""
        if self._source_thread is not None:
            self._source_stop.set()
            self._source_thread.join(timeout=5.0)
            self._source_thread = None
        if self._source:
            logger.info("Capture stopped (%s).", self.describe_source())
        self._source = None

    def _live_loop(self, sock) -> None:
        try:
            while not self._source_stop.is_set():
                if not sock.select([sock], _SELECT_TIMEOUT_S):
                    continue
                ll, data, ts = sock.recv_raw()
                if data is None:
                    continue
                self._enqueue((data, ts or time.time(), linktype_of(ll)))
        except Exception as exc:
            self._source_error = f"Capture failed: {exc}"
            logger.error(self._source_error)
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self._source = None

    def _replay_loop(self, path: str, speed: float, loop: bool) -> None:
        stop = self._source_stop
        try:
            while not stop.is_set():
                wall_start = time.time()
                first_ts: Optional[float] = None
                for data, ts, linktype in iter_raw(path):
                    if stop.is_set():
                        return
                    if first_ts is None:
                        first_ts = ts
                    if speed > 0:
                        delay = wall_start + (ts - first_ts) / speed - time.time()
                        if delay > 0:
                            stop.wait(delay)
                    self.received += 1
                    item = (data, time.time(), linktype)
                    # A file can wait for us, so block instead of dropping.
                    while not stop.is_set():
                        try:
                            self._q.put(item, timeout=0.2)
                            break
                        except queue.Full:
                            continue
                if not loop:
                    break
        except Exception as exc:
            self._source_error = f"Replay failed: {exc}"
            logger.error(self._source_error)
        finally:
            # stop() joins this thread before starting anything new, so no
            # other source can be active here.
            self._source = None

    # ------------------------------------------------------------------ #
    # Hot path
    # ------------------------------------------------------------------ #

    def _enqueue(self, frame: RawFrame) -> None:
        """Called by the source thread for every frame — keep it trivial."""
        self.received += 1
        try:
            self._q.put_nowait(frame)
        except queue.Full:
            self.dropped += 1

    def _worker_loop(self) -> None:
        interval = self._cfg.stats_snapshot_interval_s
        next_tick = time.time() + interval
        q = self._q
        while not self._worker_stop.is_set():
            timeout = max(0.0, min(0.2, next_tick - time.time()))
            try:
                frame = q.get(timeout=timeout) if timeout > 0 else q.get_nowait()
            except queue.Empty:
                frame = None
            if frame is not None:
                depth = q.qsize()
                if depth > self.max_queue_depth:
                    self.max_queue_depth = depth
                self._handle(frame)

            now = time.time()
            if now >= next_tick:
                self._tick(now)
                next_tick += interval
                if next_tick <= now:   # we fell behind; don't burst-tick
                    next_tick = now + interval

    def _handle(self, frame: RawFrame) -> None:
        t0 = time.perf_counter()
        data, ts, linktype = frame
        record = parse_frame(data, ts, linktype)
        if record is None:
            self.unparsed += 1
            return

        self._seq += 1
        record.seq = self._seq
        self.total_bytes += record.size
        with self._ring_lock:
            self._ring.append(record)

        for cb in self._packet_callbacks:
            try:
                cb(record)
            except Exception as exc:
                logger.exception("Packet callback error: %s", exc)

        self.processed += 1
        self._proc_time_s += time.perf_counter() - t0
        self._proc_count += 1

    def _tick(self, now: float) -> None:
        self._update_metrics(now)
        for cb in self._tick_callbacks:
            try:
                cb(now)
            except Exception as exc:
                logger.exception("Tick callback error: %s", exc)

    def _update_metrics(self, now: float) -> None:
        elapsed = (now - self._last_tick_time) if self._last_tick_time else None
        processed_delta = self.processed - self._last_tick_processed
        received_delta = self.received - self._last_tick_received
        dropped_delta = self.dropped - self._last_tick_dropped
        avg_us = (self._proc_time_s / self._proc_count * 1e6) if self._proc_count else None

        self._metrics = {
            "timestamp": now,
            "received_pps": round(received_delta / elapsed, 1) if elapsed else 0.0,
            "processed_pps": round(processed_delta / elapsed, 1) if elapsed else 0.0,
            "dropped_pps": round(dropped_delta / elapsed, 1) if elapsed else 0.0,
            "avg_processing_us": round(avg_us, 1) if avg_us is not None else None,
            "capacity_pps": round(1e6 / avg_us) if avg_us else None,
            "queue_depth": self._q.qsize(),
        }
        self._metrics_history.append(self._metrics)

        self._last_tick_time = now
        self._last_tick_processed = self.processed
        self._last_tick_received = self.received
        self._last_tick_dropped = self.dropped
        self._proc_time_s = 0.0
        self._proc_count = 0

    # ------------------------------------------------------------------ #
    # State accessors (thread-safe)
    # ------------------------------------------------------------------ #

    @property
    def is_running(self) -> bool:
        return (
            self._source is not None
            and self._source_thread is not None
            and self._source_thread.is_alive()
        )

    @property
    def interface(self) -> Optional[str]:
        return self._interface

    @property
    def total_packets(self) -> int:
        return self.processed

    @property
    def latest_seq(self) -> int:
        return self._seq

    def describe_source(self) -> str:
        if self._source == "live":
            return f"live on {self._interface}"
        if self._source == "replay":
            return f"replay of {os.path.basename(self._replay_path or '')}"
        return "idle"

    def get_recent_packets(self, limit: Optional[int] = None) -> list[PacketRecord]:
        """Return up to *limit* most-recent packets from the ring buffer (oldest first)."""
        with self._ring_lock:
            packets = list(self._ring)
        if limit:
            return packets[-limit:]
        return packets

    def get_packets_since(self, seq: int, limit: int = 200) -> list[PacketRecord]:
        """Packets with seq > *seq* still in the ring buffer (oldest first)."""
        out: list[PacketRecord] = []
        with self._ring_lock:
            for pkt in reversed(self._ring):
                if pkt.seq <= seq:
                    break
                out.append(pkt)
                if len(out) >= limit:
                    break
        out.reverse()
        return out

    def get_status(self) -> dict:
        running = self.is_running
        uptime = (time.time() - self.start_time) if (self.start_time and running) else 0.0
        return {
            "running": running,
            "source": self._source if running else None,
            "interface": self._interface,
            "replay_file": os.path.basename(self._replay_path) if self._replay_path else None,
            "description": self.describe_source() if running else "idle",
            "uptime_seconds": round(uptime, 1),
            "total_packets": self.processed,
            "total_bytes": self.total_bytes,
            "error": self._source_error,
        }

    def get_metrics(self) -> dict:
        received = self.received
        return {
            "received": received,
            "processed": self.processed,
            "dropped": self.dropped,
            "unparsed": self.unparsed,
            "drop_rate_pct": round(self.dropped / received * 100, 3) if received else 0.0,
            "queue_capacity": self._q.maxsize,
            "max_queue_depth": self.max_queue_depth,
            "current": self._metrics,
        }

    def get_metrics_history(self, limit: int = 300) -> list[dict]:
        return list(self._metrics_history)[-limit:]


def _explain_capture_error(exc: Optional[BaseException], interface: str) -> str:
    if isinstance(exc, PermissionError) or (exc and "not permitted" in str(exc).lower()):
        return (
            "Permission denied opening a raw socket. On Linux run the server as root, "
            "or grant the interpreter capture rights once with: "
            "sudo setcap cap_net_raw,cap_net_admin=eip \"$(readlink -f .venv/bin/python)\". "
            "On Windows run the terminal as Administrator with Npcap installed."
        )
    if exc is not None:
        return f"Could not start capture on '{interface}': {exc}"
    return f"Capture on '{interface}' did not start."
