"""Capture engine: queue/worker, live loop (fake socket), replay and drop accounting."""

import queue
import threading
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from backend.capture.engine import CaptureEngine
from backend.pipeline import Pipeline

from tests.helpers import cfg


def _frame(i: int) -> bytes:
    return bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                 TCP(sport=40000 + i % 100, dport=443, flags="S"))


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


class FakeSocket:
    """Mimics the recv_raw/select/close surface of Scapy's L2 listen sockets."""

    class LL:
        __name__ = "Ether"

    def __init__(self, frames):
        self._q = queue.Queue()
        for f in frames:
            self._q.put(f)
        self.closed = threading.Event()

    def select(self, socks, timeout):
        try:
            self._next = self._q.get(timeout=timeout)
            return socks
        except queue.Empty:
            return []

    def recv_raw(self):
        return Ether, self._next, time.time()

    def close(self):
        self.closed.set()


def test_live_loop_feeds_pipeline_and_stops_cleanly():
    c = cfg()
    engine = CaptureEngine(c)
    pipe = Pipeline(c)
    engine.add_callback(pipe.process)
    engine.start_worker()
    sock = FakeSocket([_frame(i) for i in range(50)])
    engine._begin("live", interface="fake0")
    engine._source_thread = threading.Thread(target=engine._live_loop, args=(sock,), daemon=True)
    engine._source_thread.start()
    try:
        assert _wait(lambda: engine.processed == 50)
        assert engine.is_running
        assert engine.get_packets_since(45)[-1].seq == 50
        assert pipe.flows.get_stats()["active_flows"] == 50
    finally:
        engine.stop()
        engine.stop_worker()
    assert sock.closed.is_set() and not engine.is_running


def test_full_queue_counts_drops():
    engine = CaptureEngine(cfg(capture_queue_size=10))   # worker not started
    for i in range(25):
        engine._enqueue((_frame(i), 0.0, 1))
    m = engine.get_metrics()
    assert (m["received"], m["dropped"]) == (25, 15)
    assert m["drop_rate_pct"] == 60.0


def test_replay_restamps_and_finishes(tmp_path):
    pkts = [Ether(_frame(i)) for i in range(30)]
    for i, p in enumerate(pkts):
        p.time = 1_000_000.0 + i * 0.001
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pkts)

    engine = CaptureEngine(cfg())
    seen = []
    engine.add_callback(seen.append)
    engine.start_worker()
    try:
        before = time.time()
        engine.start_replay(str(path), speed=0)
        assert _wait(lambda: len(seen) == 30)
        assert _wait(lambda: not engine.is_running)
        assert all(r.timestamp >= before for r in seen)     # re-stamped to "now"
    finally:
        engine.stop()
        engine.stop_worker()


def test_worker_ticks_without_traffic():
    c = cfg(stats_snapshot_interval_s=0.1)
    engine = CaptureEngine(c)
    ticks = []
    engine.add_tick_callback(ticks.append)
    engine.start_worker()
    try:
        assert _wait(lambda: len(ticks) >= 3, timeout=2)
    finally:
        engine.stop_worker()
