"""
Record ground-truth timestamps while running a lab scenario.

    python -m evaluation.mark --labels captures/lab1.labels.json start PORT_SCAN \
        --source 10.10.0.66 --target 10.10.0.20 --note "scan scenario"
    ... run the scenario in your isolated lab ...
    python -m evaluation.mark --labels captures/lab1.labels.json end PORT_SCAN

    python -m evaluation.mark --labels captures/lab1.labels.json show

`start` appends an open incident stamped with the current time; `end`
closes the most recent open incident of that type.  Times are absolute
(Unix epoch), matching the timestamps your capture tool records — run this
on the capture machine, or keep the clocks synchronised.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from evaluation.metrics import ALERT_TYPES


def _load(path: str) -> dict:
    if os.path.isfile(path):
        with open(path) as fh:
            return json.load(fh)
    return {"description": "", "time_base": "absolute", "network": {}, "incidents": []}


def _save(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels", required=True, help="labels JSON file (created if missing)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("type", choices=ALERT_TYPES)
    s.add_argument("--source")
    s.add_argument("--target")
    s.add_argument("--note", default="")
    e = sub.add_parser("end")
    e.add_argument("type", choices=ALERT_TYPES)
    sub.add_parser("show")
    args = ap.parse_args(argv)

    data = _load(args.labels)
    if data.get("time_base", "absolute") != "absolute":
        print("mark only works with absolute time_base labels.", file=sys.stderr)
        return 1
    now = round(time.time(), 3)

    if args.cmd == "start":
        data["incidents"].append({
            "type": args.type, "start": now, "end": None,
            "source": args.source, "target": args.target, "note": args.note,
        })
        _save(args.labels, data)
        print(f"{args.type} started at {now}")
    elif args.cmd == "end":
        for inc in reversed(data["incidents"]):
            if inc["type"] == args.type and inc.get("end") is None:
                inc["end"] = now
                _save(args.labels, data)
                print(f"{args.type} ended at {now} ({now - inc['start']:.1f}s)")
                break
        else:
            print(f"No open {args.type} incident.", file=sys.stderr)
            return 1
    else:
        for inc in data["incidents"]:
            end = inc.get("end")
            dur = f"{end - inc['start']:.1f}s" if end else "OPEN"
            print(f"{inc['type']:<14} {inc['start']:.3f}  {dur:>8}  {inc.get('note', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
