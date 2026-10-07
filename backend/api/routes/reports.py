"""
GET /reports/summary     — historical summary for the Reports view
GET /reports/diagnosis   — "Why is (or was) my network slow?"
GET /reports/evaluation  — latest evaluation results, if any have been run

Reports read persisted 1-second snapshots from the database, so they cover
any time range (not just what is still in memory) and survive restarts.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict
from typing import Optional

from fastapi import APIRouter, Query

from backend.api.state import anomaly_detector, stats_engine
from backend.config import settings
from backend.storage.database import alerts_between, flow_totals_between, snapshots_between

router = APIRouter(tags=["reports"])

_MAX_POINTS = 120
_DEGRADED_SCORE = 70
_EVAL_RESULTS = os.path.join("evaluation", "results", "latest.json")


@router.get("/reports/summary")
def report_summary(minutes: float = Query(60, ge=1, le=7 * 24 * 60)):
    end = time.time()
    start = end - minutes * 60
    snaps = snapshots_between(start, end)
    alerts = alerts_between(start, end)
    services = flow_totals_between(start, end)

    if not snaps:
        return {
            "range": {"start": start, "end": end, "minutes": minutes},
            "message": "No stored data for this range yet.",
            "alerts": _alert_section(alerts),
            "services": services,
        }

    total_bytes = sum(s.interval_bytes or 0 for s in snaps)
    total_packets = sum(s.interval_packets or 0 for s in snaps)
    totals_bps = [(s.download_bps or 0) + (s.upload_bps or 0) + (s.lan_bps or 0) for s in snaps]
    latencies = [s.latency_ms for s in snaps if s.latency_ms is not None]
    healths = [s.health_score for s in snaps if s.health_score is not None]

    # Protocol mix: each snapshot's share × the packets seen that second
    proto_packets: dict[str, float] = defaultdict(float)
    for s in snaps:
        for proto, d in (s.protocol_dist or {}).items():
            proto_packets[proto] += d.get("pct", 0) / 100 * (s.interval_packets or 0)
    proto_total = sum(proto_packets.values()) or 1
    protocols = [
        {"protocol": p, "packets": round(n), "pct": round(n / proto_total * 100, 1)}
        for p, n in sorted(proto_packets.items(), key=lambda kv: -kv[1])
    ]

    # Top devices / destinations: each snapshot holds rolling-window byte
    # counts, so dividing the sum by the window length estimates bytes.
    window = settings.stats_rolling_window_s
    top_devices = _aggregate_ranked((s.top_talkers or [] for s in snaps), window)
    top_destinations = _aggregate_ranked((s.top_destinations or [] for s in snaps), window)

    # Recurring health problems
    issue_counts: Counter = Counter()
    latest_reason: dict[str, str] = {}
    culprits: Counter = Counter()
    for s in snaps:
        for issue in s.health_issues or []:
            if not isinstance(issue, dict):
                continue
            issue_counts[issue["name"]] += 1
            latest_reason[issue["name"]] = issue["reason"]
            if issue.get("culprit"):
                culprits[issue["culprit"]["ip"]] += 1

    return {
        "range": {"start": start, "end": end, "minutes": minutes, "samples": len(snaps)},
        "traffic": {
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "avg_bps": round(sum(totals_bps) / len(totals_bps)),
            "peak_bps": round(max(totals_bps)),
            "peak_at": snaps[totals_bps.index(max(totals_bps))].timestamp,
        },
        "latency": {
            "avg_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "max_ms": round(max(latencies), 2) if latencies else None,
        },
        "health": {
            "avg": round(sum(healths) / len(healths), 1) if healths else None,
            "min": min(healths) if healths else None,
            "latest": healths[-1] if healths else None,
            "degraded_seconds": sum(1 for h in healths if h < _DEGRADED_SCORE),
            "recurring_issues": [
                {"component": name, "seconds": n, "latest_reason": latest_reason[name]}
                for name, n in issue_counts.most_common()
            ],
            "frequent_culprits": [{"ip": ip, "seconds": n} for ip, n in culprits.most_common(5)],
        },
        "protocols": protocols,
        "top_devices": top_devices,
        "top_destinations": top_destinations,
        "services": services,
        "trend": _downsample(snaps),
        "alerts": _alert_section(alerts),
    }


@router.get("/reports/diagnosis")
def diagnosis(minutes: float = Query(30, ge=1, le=24 * 60)):
    """
    Plain-language answer to "why is my network slow?" built from the live
    health breakdown, plus the degraded periods in the recent past.
    """
    snap = stats_engine.latest_snapshot()
    now_section: Optional[dict] = None
    if snap is not None:
        comps = sorted(snap.health["components"], key=lambda c: -c.get("points_lost", 0))
        causes = [c for c in comps if c.get("points_lost", 0) >= 1]
        if causes:
            headline = (
                f"Network health is {snap.health_score}/100. Main factor: "
                f"{causes[0]['name'].replace('_', ' ')} — {causes[0]['reason']}"
            )
        else:
            headline = f"Network health is {snap.health_score}/100 — no significant problems right now."
        recent = [
            a.to_dict() for a in anomaly_detector.recent_unresolved(
                snap.timestamp, settings.health_alert_horizon_s)
        ][:5]
        now_section = {
            "health_score": snap.health_score,
            "headline": headline,
            "causes": causes,
            "chain": _causal_chain(snap, causes, recent),
            "related_alerts": recent,
        }

    end = time.time()
    snaps = snapshots_between(end - minutes * 60, end)
    periods = _degraded_periods(snaps)
    return {"now": now_section, "degraded_periods": periods, "window_minutes": minutes}


@router.get("/reports/evaluation")
def evaluation_results():
    """Latest output of the evaluation harness (evaluation/results/latest.json)."""
    if not os.path.isfile(_EVAL_RESULTS):
        return {"available": False, "message": "No evaluation has been run yet."}
    with open(_EVAL_RESULTS) as fh:
        return {"available": True, **json.load(fh)}


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _aggregate_ranked(lists, window: float, n: int = 10) -> list[dict]:
    totals: dict[str, float] = defaultdict(float)
    names: dict[str, str] = {}
    for entries in lists:
        for e in entries:
            totals[e["ip"]] += e.get("bytes", 0) / window
            if e.get("name"):
                names[e["ip"]] = e["name"]
    grand = sum(totals.values()) or 1
    ranked = sorted(totals.items(), key=lambda kv: -kv[1])[:n]
    return [
        {"ip": ip, "name": names.get(ip, ip), "approx_bytes": round(b),
         "pct": round(b / grand * 100, 1)}
        for ip, b in ranked
    ]


def _downsample(snaps) -> list[dict]:
    if not snaps:
        return []
    step = max(1, len(snaps) // _MAX_POINTS)
    out = []
    for i in range(0, len(snaps), step):
        chunk = snaps[i:i + step]
        lat = [s.latency_ms for s in chunk if s.latency_ms is not None]
        hs = [s.health_score for s in chunk if s.health_score is not None]
        out.append({
            "timestamp": chunk[-1].timestamp,
            "download_bps": round(sum(s.download_bps or 0 for s in chunk) / len(chunk)),
            "upload_bps": round(sum(s.upload_bps or 0 for s in chunk) / len(chunk)),
            "lan_bps": round(sum(s.lan_bps or 0 for s in chunk) / len(chunk)),
            "packets_per_sec": round(max(s.packets_per_sec or 0 for s in chunk), 1),
            "latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
            "health_score": round(sum(hs) / len(hs)) if hs else None,
            "active_connections": max(s.active_connections or 0 for s in chunk),
        })
    return out


def _alert_section(alerts: list[dict]) -> dict:
    return {
        "total": len(alerts),
        "by_type": dict(Counter(a["alert_type"] for a in alerts)),
        "by_severity": dict(Counter(a["severity"] for a in alerts)),
        "recent": list(reversed(alerts[-50:])),
    }


_TYPE_LABEL = {"PORT_SCAN": "Port scan", "SYN_FLOOD": "SYN flood",
               "ARP_ANOMALY": "ARP anomaly", "TRAFFIC_SPIKE": "Traffic spike"}


def _causal_chain(snap, causes: list[dict], recent_alerts: list[dict]) -> list[str]:
    """E.g. ["High bandwidth utilisation", "Device 192.168.1.15", "68% of total traffic"]."""
    if not causes:
        return []
    top = causes[0]
    chain = [f"{top['name'].replace('_', ' ').capitalize()}: {top['value']} {top['unit']}"]
    culprit = top.get("culprit")
    if culprit:
        chain.append(f"Device {culprit['name']} ({culprit['ip']})")
        chain.append(f"{culprit['pct']:.0f}% of total traffic")
    elif top["name"] == "threats" and recent_alerts:
        a = recent_alerts[0]
        chain.append(f"{_TYPE_LABEL.get(a['alert_type'], a['alert_type'])} "
                     f"({a['severity'].lower()}) from {a['source_ip'] or 'unknown source'}")
        if a.get("target_ip"):
            chain.append(f"targeting {a['target_ip']}")
    elif top["name"] == "latency" and snap.top_destinations:
        d = snap.top_destinations[0]
        chain.append(f"Busiest destination: {d['name']} ({d['pct']:.0f}% of traffic)")
    return chain


def _degraded_periods(snaps) -> list[dict]:
    periods: list[dict] = []
    current: Optional[dict] = None
    for s in snaps:
        degraded = s.health_score is not None and s.health_score < _DEGRADED_SCORE
        if degraded:
            if current is None:
                current = {"start": s.timestamp, "end": s.timestamp,
                           "min_score": s.health_score, "issues": Counter()}
            current["end"] = s.timestamp
            current["min_score"] = min(current["min_score"], s.health_score)
            for issue in s.health_issues or []:
                if isinstance(issue, dict):
                    current["issues"][issue["name"]] += 1
        elif current is not None:
            periods.append(current)
            current = None
    if current is not None:
        periods.append(current)
    return [
        {
            "start": p["start"], "end": p["end"],
            "duration_s": round(p["end"] - p["start"] + 1),
            "min_score": p["min_score"],
            "main_issue": p["issues"].most_common(1)[0][0] if p["issues"] else None,
        }
        for p in periods[-20:]
    ]
