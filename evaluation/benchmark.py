"""
Live-path throughput and packet-drop benchmark (evaluation/benchmark.py)

    python -m evaluation.benchmark captures/lab1.pcap --rates 1000 5000 10000 20000 --seconds 10

Measures the real capture path — CaptureEngine's bounded queue, its
analysis worker, the parser and the full adaptive pipeline — by offering
packets from a capture file at fixed rates, in process.  For each offered
rate it reports:

  • processed packets/sec actually sustained
  • drop rate: packets the queue could not accept ÷ packets offered
  • mean per-packet processing time

The sniffer thread is replaced by a paced feeder thread calling the same
enqueue function the sniffer uses, so everything downstream of the kernel
is exercised.  Kernel/NIC-level drops (before NetVision sees a packet) are
outside this measurement; on Linux compare with `ip -s link`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time

from backend.capture.engine import CaptureEngine
from backend.capture.pcapfile import iter_raw
from backend.config import Settings
from backend.pipeline import Pipeline
from evaluation import charts
from evaluation.run_eval import RESULTS_DIR


def load_raw(path: str, limit: int) -> list:
    out = []
    for frame in iter_raw(path):
        out.append(frame)
        if len(out) >= limit:
            break
    return out


def run_rate(raw_packets: list, rate: int, seconds: float, queue_size: int) -> dict:
    cfg = Settings(database_url="sqlite://", capture_queue_size=queue_size)
    engine = CaptureEngine(cfg)
    pipe = Pipeline(cfg, "adaptive")
    engine.add_callback(pipe.process)
    engine.add_tick_callback(lambda now: pipe.tick(now))
    engine.start_worker()

    stop = threading.Event()
    offered = 0

    def feeder():
        nonlocal offered
        start = time.perf_counter()
        n = len(raw_packets)
        i = 0
        while not stop.is_set():
            elapsed = time.perf_counter() - start
            if elapsed >= seconds:
                break
            due = int(elapsed * rate)
            while offered < due:
                data, _, linktype = raw_packets[i % n]
                engine._enqueue((data, time.time(), linktype))
                offered += 1
                i += 1
            time.sleep(0.0005)

    t0 = time.perf_counter()
    th = threading.Thread(target=feeder, daemon=True)
    th.start()
    th.join()
    feed_time = time.perf_counter() - t0
    processed_at_end = engine.processed + engine.unparsed

    # Let the worker drain what was accepted, timing the whole run.
    drain_deadline = time.time() + 60
    while engine._q.qsize() and time.time() < drain_deadline:
        time.sleep(0.05)
    total_time = time.perf_counter() - t0
    engine.stop_worker()

    handled = engine.processed + engine.unparsed
    return {
        "offered_rate_pps": rate,
        "offered": offered,
        "accepted": offered - engine.dropped,
        "dropped": engine.dropped,
        "drop_rate_pct": round(engine.dropped / offered * 100, 3) if offered else 0.0,
        "processed_pps_during_feed": round(processed_at_end / feed_time),
        "processed_pps_overall": round(handled / total_time),
        "max_queue_depth": engine.max_queue_depth,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture")
    ap.add_argument("--rates", type=int, nargs="+", default=[1_000, 2_500, 5_000, 10_000, 20_000])
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--queue", type=int, default=20_000, help="capture queue size")
    ap.add_argument("--max-packets", type=int, default=50_000)
    ap.add_argument("--name", default="benchmark")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.ERROR)

    raw = load_raw(args.capture, args.max_packets)
    if not raw:
        raise SystemExit("capture is empty")
    print(f"Loaded {len(raw):,} packets from {args.capture}")

    rows = []
    for rate in args.rates:
        r = run_rate(raw, rate, args.seconds, args.queue)
        rows.append(r)
        print(f"  offered {rate:>6,} pps → processed {r['processed_pps_during_feed']:>6,} pps, "
              f"dropped {r['drop_rate_pct']:.2f}% (max queue {r['max_queue_depth']:,})")

    out = os.path.join(RESULTS_DIR, args.name)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "benchmark.json"), "w") as fh:
        json.dump({"capture": args.capture, "seconds_per_rate": args.seconds,
                   "queue_size": args.queue, "results": rows}, fh, indent=2)
    _chart(rows, os.path.join(out, "benchmark.png"))
    print(f"Results written to {out}/benchmark.json and benchmark.png")
    return 0


def _chart(rows: list[dict], path: str) -> None:
    """Two small multiples on a shared x: sustained rate, and drop rate."""
    import matplotlib.pyplot as plt
    charts._style()
    xs = [r["offered_rate_pps"] for r in rows]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 3.6), dpi=150)
    a1.plot(xs, xs, color=charts.AXIS, lw=1, zorder=1)
    a1.plot(xs, [r["processed_pps_during_feed"] for r in rows], color="#2a78d6", lw=2,
            marker="o", markersize=6, markeredgecolor=charts.SURFACE, markeredgewidth=2, zorder=2)
    a1.text(xs[-1], xs[-1], " offered", color=charts.MUTED, fontsize=8, va="center")
    a1.set_title("Sustained processing rate")
    a1.set_xlabel("Offered packets/s")
    a1.set_ylabel("Processed packets/s")
    a2.plot(xs, [r["drop_rate_pct"] for r in rows], color="#2a78d6", lw=2,
            marker="o", markersize=6, markeredgecolor=charts.SURFACE, markeredgewidth=2)
    a2.set_title("Packet drop rate")
    a2.set_xlabel("Offered packets/s")
    a2.set_ylabel("Dropped (%)")
    # A floor of 1% keeps an all-zero result from auto-scaling to noise.
    a2.set_ylim(0, max(1.0, max(r["drop_rate_pct"] for r in rows) * 1.2))
    charts.thousands(a1)
    charts.thousands(a2, "x")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


if __name__ == "__main__":
    sys.exit(main())
