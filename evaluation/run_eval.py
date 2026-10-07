"""
Static vs adaptive evaluation on labelled captures (evaluation/run_eval.py)

    python -m evaluation.run_eval captures/lab1.pcap [captures/lab2.pcap ...] \
        [--name lab-oct] [--grace 5] [--bin 10] [--set port_scan_threshold=20]

For each capture (with its `<name>.labels.json` alongside):
  1. parse every packet once with the production parser (timed);
  2. replay the parsed packets through two fresh pipelines — static and
     adaptive — ticking on packet time, so both see identical input (timed);
  3. score each mode's alerts against the labelled incidents.

Outputs (evaluation/results/<name>/):
  summary.json        everything below, machine-readable
  metrics.csv         one row per mode × alert type (the table view of every chart)
  alerts_<mode>.csv   every alert with its explanation summary
  quality.png         precision / recall / F1
  fpr.png             false-positive rate per detector
  latency.png         median detection latency per attack type
  timeline_<case>.png throughput, incident windows and alerts over time
  report.md           tables ready to paste into the project report

evaluation/results/latest.json is also written; the dashboard's Reports
view shows it.  Processing throughput here is offline (single thread, no
capture); use evaluation.benchmark for live-path throughput and drop rate.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime

from backend.capture.pcapfile import iter_raw
from backend.config import Settings
from backend.parser.fast_parser import parse_frame
from backend.pipeline import Pipeline
from evaluation import charts
from evaluation.labels import incidents_to_json, labels_path_for, load_labels
from evaluation.metrics import ALERT_TYPES, AlertPoint, merge, score

RESULTS_DIR = os.path.join("evaluation", "results")
MODES = ("static", "adaptive")


def parse_capture(path: str) -> tuple[list, float]:
    """Return (records, parse_seconds) using the same fast parser as the server."""
    frames = list(iter_raw(path))
    records = []
    t0 = time.perf_counter()
    for data, ts, linktype in frames:
        rec = parse_frame(data, ts, linktype)
        if rec is not None:
            records.append(rec)
    elapsed = time.perf_counter() - t0
    records.sort(key=lambda r: r.timestamp)
    for i, r in enumerate(records, 1):
        r.seq = i
    return records, elapsed


def run_mode(records, cfg: Settings, mode: str, network: dict):
    pipe = Pipeline(cfg, mode)
    if network:
        pipe.hosts.configure_interface(
            network.get("self_ips", []), network.get("local_networks", []), network.get("gateway"))
        pipe.detector.set_gateway(network.get("gateway"))
    throughput: list[tuple[float, float]] = []
    orig_tick = pipe.tick

    def tick(now):
        snap, alerts = orig_tick(now)
        throughput.append((now, snap.instant_bps))
        return snap, alerts

    pipe.tick = tick
    t0 = time.perf_counter()
    alerts = pipe.run_offline(records)
    elapsed = time.perf_counter() - t0
    return alerts, elapsed, throughput


def evaluate_case(path: str, cfg: Settings, grace: float, bin_s: float, labels: str | None):
    records, parse_s = parse_capture(path)
    if not records:
        raise SystemExit(f"{path}: no parseable packets")
    t_start, t_end = records[0].timestamp, records[-1].timestamp
    lab = load_labels(labels or labels_path_for(path), first_packet_ts=t_start)

    case = {
        "name": os.path.splitext(os.path.basename(path))[0],
        "file": path,
        "description": lab["description"],
        "packets": len(records),
        "t_start": t_start,
        "t_end": t_end,
        "incidents": incidents_to_json(lab["incidents"]),
        "parse_seconds": parse_s,
        "alerts": {},
        "pipeline_seconds": {},
        "scores": {},
    }
    for mode in MODES:
        alerts, elapsed, throughput = run_mode(records, cfg, mode, lab["network"])
        points = [AlertPoint(a.alert_type, a.timestamp, a.alert_id) for a in alerts]
        case["scores"][mode] = score(points, lab["incidents"], t_start, t_end, grace, bin_s)
        case["alerts"][mode] = [a.to_dict() for a in alerts]
        case["pipeline_seconds"][mode] = elapsed
        if mode == "adaptive":
            case["throughput"] = throughput
    return case


def write_outputs(name: str, cases: list[dict], cfg_overrides: dict) -> str:
    out = os.path.join(RESULTS_DIR, name)
    os.makedirs(out, exist_ok=True)

    totals = {m: merge([c["scores"][m] for c in cases]).to_dict() for m in MODES}
    n_packets = sum(c["packets"] for c in cases)
    parse_s = sum(c["parse_seconds"] for c in cases)
    perf = {
        "packets": n_packets,
        "parse_pps": round(n_packets / parse_s) if parse_s else None,
        **{
            f"pipeline_pps_{m}": round(n_packets / s) if (s := sum(c["pipeline_seconds"][m] for c in cases)) else None
            for m in MODES
        },
    }
    end_to_end = parse_s + sum(c["pipeline_seconds"]["adaptive"] for c in cases)
    perf["end_to_end_pps_adaptive"] = round(n_packets / end_to_end) if end_to_end else None

    summary = {
        "name": name,
        "generated_at": time.time(),
        "generated_at_iso": datetime.now().isoformat(timespec="seconds"),
        "settings_overrides": cfg_overrides,
        "cases": [
            {
                "name": c["name"], "file": c["file"], "description": c["description"],
                "packets": c["packets"], "duration_s": round(c["t_end"] - c["t_start"], 1),
                "incidents": c["incidents"],
                "results": {m: c["scores"][m].to_dict() for m in MODES},
            }
            for c in cases
        ],
        "results": totals,
        "performance": perf,
        "charts": {
            "quality": f"{name}/quality.png", "fpr": f"{name}/fpr.png",
            "latency": f"{name}/latency.png",
            "timelines": [f"{name}/timeline_{c['name']}.png" for c in cases],
        },
    }

    with open(os.path.join(out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    with open(os.path.join(RESULTS_DIR, "latest.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    _write_metrics_csv(os.path.join(out, "metrics.csv"), totals)
    for m in MODES:
        _write_alerts_csv(os.path.join(out, f"alerts_{m}.csv"), cases, m)

    charts.quality_chart(totals, os.path.join(out, "quality.png"))
    charts.fpr_chart(totals, os.path.join(out, "fpr.png"))
    charts.latency_chart(totals, os.path.join(out, "latency.png"))
    for c in cases:
        charts.timeline_chart(
            {"name": c["name"], "t_start": c["t_start"], "throughput": c["throughput"],
             "incidents": c["incidents"], "alerts": c["alerts"]},
            os.path.join(out, f"timeline_{c['name']}.png"),
        )

    with open(os.path.join(out, "report.md"), "w") as fh:
        fh.write(_markdown(summary))
    return out


def _write_metrics_csv(path: str, totals: dict) -> None:
    cols = ["mode", "alert_type", "incidents", "detected", "alerts", "true_positives",
            "false_positives", "secondary_alerts", "precision", "recall", "f1", "fpr",
            "latency_median_s", "latency_mean_s", "latency_max_s"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for m in MODES:
            for t in (*ALERT_TYPES, "ALL"):
                row = totals[m]["overall"] if t == "ALL" else totals[m]["per_type"][t]
                w.writerow({"mode": m, **row, "alert_type": t})


def _write_alerts_csv(path: str, cases: list[dict], mode: str) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case", "timestamp", "alert_type", "severity", "source", "target",
                    "observed", "threshold", "summary"])
        for c in cases:
            for a in c["alerts"][mode]:
                ex = a.get("explanation") or {}
                w.writerow([c["name"], a["timestamp"], a["alert_type"], a["severity"],
                            a["source_ip"], a["target_ip"], ex.get("observed"),
                            ex.get("threshold"), ex.get("summary")])


def _fmt(v, pct=False, unit=""):
    if v is None:
        return "—"
    return f"{v * 100:.1f}%" if pct else f"{v:.2f}{unit}"


def _markdown(s: dict) -> str:
    r = s["results"]
    lines = [
        f"# NetVision evaluation — {s['name']}",
        "",
        f"Generated {s['generated_at_iso']}. "
        f"{len(s['cases'])} capture(s), {s['performance']['packets']:,} packets, "
        f"{sum(len(c['incidents']) for c in s['cases'])} labelled incident(s).",
        "",
        "## Overall",
        "",
        "| Metric | Static | Adaptive |",
        "|---|---|---|",
    ]
    for key, label, pct in (("precision", "Precision", False), ("recall", "Recall", False),
                            ("f1", "F1-score", False), ("fpr", "False-positive rate", True)):
        lines.append(f"| {label} | {_fmt(r['static']['overall'][key], pct)} | "
                     f"{_fmt(r['adaptive']['overall'][key], pct)} |")
    lines.append(
        f"| False alerts / normal hour | {r['static']['false_alerts_per_normal_hour']} | "
        f"{r['adaptive']['false_alerts_per_normal_hour']} |")
    lines.append(
        f"| Median detection latency | {_fmt(r['static']['overall']['latency_median_s'], unit=' s')} | "
        f"{_fmt(r['adaptive']['overall']['latency_median_s'], unit=' s')} |")

    lines += ["", "## Per detector", "",
              "| Detector | Mode | Incidents | Detected | TP | FP | Precision | Recall | FPR | Median latency |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for t in ALERT_TYPES:
        for m in MODES:
            d = r[m]["per_type"][t]
            lines.append(
                f"| {charts.TYPE_LABEL[t]} | {m} | {d['incidents']} | {d['detected']} | "
                f"{d['true_positives']} | {d['false_positives']} | {_fmt(d['precision'])} | "
                f"{_fmt(d['recall'])} | {_fmt(d['fpr'], True)} | {_fmt(d['latency_median_s'], unit=' s')} |")

    p = s["performance"]
    lines += ["", "## Processing throughput (offline, single thread)", "",
              f"- Parsing: {p['parse_pps']:,} packets/s" if p["parse_pps"] else "- Parsing: —",
              f"- Analysis pipeline (static): {p['pipeline_pps_static']:,} packets/s",
              f"- Analysis pipeline (adaptive): {p['pipeline_pps_adaptive']:,} packets/s",
              f"- Parse + adaptive analysis end to end: {p['end_to_end_pps_adaptive']:,} packets/s",
              "",
              "Live-capture throughput and packet drop rate: see `python -m evaluation.benchmark`.",
              "",
              "## Method", "",
              f"Alerts within an incident window (+{s['cases'][0]['results']['static']['grace_s']:.0f} s grace) "
              "of the same type are true positives; alerts inside a different incident type are "
              "counted as secondary (excluded from precision); all others are false positives. "
              f"FPR is the share of {s['cases'][0]['results']['static']['bin_s']:.0f}-second bins "
              "of normal traffic containing at least one alert.", ""]
    return "\n".join(lines)


def _parse_overrides(pairs: list[str]) -> dict:
    out = {}
    for p in pairs:
        k, _, v = p.partition("=")
        if not k or not v:
            raise SystemExit(f"--set expects key=value, got {p!r}")
        out[k.strip()] = v.strip()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+", help="pcap / pcapng files with .labels.json alongside")
    ap.add_argument("--labels", help="labels file (only with a single capture)")
    ap.add_argument("--name", default=None, help="results folder name")
    ap.add_argument("--grace", type=float, default=5.0, help="seconds after an incident still credited")
    ap.add_argument("--bin", type=float, default=10.0, help="bin size for false-positive rate")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="override a Settings field, e.g. port_scan_threshold=20")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.ERROR)
    if args.labels and len(args.captures) > 1:
        raise SystemExit("--labels can only be used with a single capture")

    overrides = _parse_overrides(args.set)
    cfg = Settings(**overrides, database_url="sqlite://")
    name = args.name or datetime.now().strftime("run-%Y%m%d-%H%M%S")

    cases = []
    for path in args.captures:
        print(f"Evaluating {path} …", flush=True)
        case = evaluate_case(path, cfg, args.grace, args.bin, args.labels)
        for m in MODES:
            o = case["scores"][m].overall
            print(f"  {m:<9} alerts={o.alerts:<4} TP={o.true_positives:<4} FP={o.false_positives:<4} "
                  f"detected={o.detected}/{o.incidents}")
        cases.append(case)

    out = write_outputs(name, cases, overrides)
    print(f"\nResults written to {out}/ (report.md, metrics.csv, charts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
