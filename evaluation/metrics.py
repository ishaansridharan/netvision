"""
Detection-quality metrics (evaluation/metrics.py)

Ground truth is a list of labelled incidents: (type, start, end).  Alerts
are matched to incidents per alert type.

Definitions
───────────
For each alert type T:

  • An alert of type T is a TRUE POSITIVE if its timestamp falls inside an
    incident of type T, extended by `grace_s` after the incident ends
    (detection may legitimately trail the last attack packet).
  • An alert of type T that falls inside an incident of a *different* type
    is SECONDARY — a symptom of the labelled attack (e.g. a SYN flood also
    spikes throughput).  Secondary alerts are reported, but count neither
    for nor against precision.
  • Every other alert of type T is a FALSE POSITIVE.
  • An incident is DETECTED if at least one true-positive alert matched it.
    Detection latency = first matching alert − incident start.

  precision = TP alerts / (TP + FP alerts)
  recall    = detected incidents / incidents
  F1        = harmonic mean of precision and recall

False-positive rate
───────────────────
Alerts are not a fixed set of classified items, so FPR is defined over
time bins: the capture is cut into `bin_s`-second bins; a bin is NORMAL for
type T if it does not overlap any labelled incident (of any type, with
grace).  FPR(T) = normal bins containing ≥ 1 type-T alert / normal bins.
Overall FPR uses "any alert" in a normal bin.  Also reported: false
alerts per hour of normal traffic.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Optional

ALERT_TYPES = ("PORT_SCAN", "SYN_FLOOD", "ARP_ANOMALY", "TRAFFIC_SPIKE")


@dataclass
class Incident:
    type: str
    start: float
    end: float
    source: Optional[str] = None
    target: Optional[str] = None
    note: str = ""


@dataclass
class AlertPoint:
    type: str
    timestamp: float
    alert_id: str = ""


@dataclass
class TypeResult:
    alert_type: str
    incidents: int = 0
    detected: int = 0
    alerts: int = 0
    true_positives: int = 0
    false_positives: int = 0
    secondary: int = 0
    normal_bins: int = 0
    fp_bins: int = 0
    latencies: list[float] = field(default_factory=list)

    @property
    def precision(self) -> Optional[float]:
        judged = self.true_positives + self.false_positives
        return self.true_positives / judged if judged else None

    @property
    def recall(self) -> Optional[float]:
        return self.detected / self.incidents if self.incidents else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None if (p is None or r is None) else 0.0
        return 2 * p * r / (p + r)

    @property
    def fpr(self) -> Optional[float]:
        return self.fp_bins / self.normal_bins if self.normal_bins else None

    def to_dict(self) -> dict:
        lat = self.latencies
        return {
            "alert_type": self.alert_type,
            "incidents": self.incidents,
            "detected": self.detected,
            "alerts": self.alerts,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "secondary_alerts": self.secondary,
            "precision": _r(self.precision),
            "recall": _r(self.recall),
            "f1": _r(self.f1),
            "fpr": _r(self.fpr),
            "normal_bins": self.normal_bins,
            "fp_bins": self.fp_bins,
            "latency_mean_s": _r(sum(lat) / len(lat)) if lat else None,
            "latency_median_s": _r(_median(lat)) if lat else None,
            "latency_max_s": _r(max(lat)) if lat else None,
        }


@dataclass
class Score:
    """Raw counts for one capture (or several, merged)."""
    per_type: dict[str, TypeResult]
    overall: TypeResult
    span_s: float
    bin_s: float
    grace_s: float

    @property
    def normal_hours(self) -> float:
        return self.overall.normal_bins * self.bin_s / 3600

    def to_dict(self) -> dict:
        hours = self.normal_hours
        return {
            "span_s": round(self.span_s, 1),
            "bin_s": self.bin_s,
            "grace_s": self.grace_s,
            "normal_hours": round(hours, 3),
            "false_alerts_per_normal_hour": (
                round(self.overall.false_positives / hours, 2) if hours else None
            ),
            "overall": self.overall.to_dict(),
            "per_type": {t: r.to_dict() for t, r in self.per_type.items()},
        }


def merge(scores: list[Score]) -> Score:
    """Micro-average several captures by summing their raw counts."""
    def add(dst: TypeResult, src: TypeResult) -> None:
        for f in ("incidents", "detected", "alerts", "true_positives",
                  "false_positives", "secondary", "normal_bins", "fp_bins"):
            setattr(dst, f, getattr(dst, f) + getattr(src, f))
        dst.latencies += src.latencies

    per_type = {t: TypeResult(alert_type=t) for t in ALERT_TYPES}
    overall = TypeResult(alert_type="ALL")
    for s in scores:
        for t in ALERT_TYPES:
            add(per_type[t], s.per_type[t])
        add(overall, s.overall)
    return Score(per_type, overall, sum(s.span_s for s in scores),
                 scores[0].bin_s if scores else 10.0,
                 scores[0].grace_s if scores else 5.0)


def evaluate(
    alerts: Iterable[AlertPoint],
    incidents: list[Incident],
    t_start: float,
    t_end: float,
    grace_s: float = 5.0,
    bin_s: float = 10.0,
) -> dict:
    """Score *alerts* against *incidents*; returns the JSON-ready summary."""
    return score(alerts, incidents, t_start, t_end, grace_s, bin_s).to_dict()


def score(
    alerts: Iterable[AlertPoint],
    incidents: list[Incident],
    t_start: float,
    t_end: float,
    grace_s: float = 5.0,
    bin_s: float = 10.0,
) -> Score:
    """Score *alerts* against *incidents* over the capture span [t_start, t_end]."""
    alerts = sorted(alerts, key=lambda a: a.timestamp)
    n_bins = max(1, math.ceil((t_end - t_start) / bin_s))

    # Bins that overlap any incident (± grace) are not "normal".
    attack_bins: set[int] = set()
    for inc in incidents:
        lo = max(0, int((inc.start - t_start) // bin_s))
        hi = min(n_bins - 1, int((inc.end + grace_s - t_start) // bin_s))
        attack_bins.update(range(lo, hi + 1))
    normal_bins = [b for b in range(n_bins) if b not in attack_bins]
    normal_set = set(normal_bins)

    per_type: dict[str, TypeResult] = {}
    any_alert_bins: set[int] = set()
    for t in ALERT_TYPES:
        res = TypeResult(alert_type=t)
        type_incs = [i for i in incidents if i.type == t]
        other_incs = [i for i in incidents if i.type != t]
        res.incidents = len(type_incs)
        res.normal_bins = len(normal_bins)
        first_hit: dict[int, float] = {}
        fp_bins: set[int] = set()

        for a in (a for a in alerts if a.type == t):
            res.alerts += 1
            match = _match(a.timestamp, type_incs, grace_s)
            if match is not None:
                res.true_positives += 1
                first_hit.setdefault(match, a.timestamp)
            elif _match(a.timestamp, other_incs, grace_s) is not None:
                res.secondary += 1
            else:
                res.false_positives += 1
            b = int((a.timestamp - t_start) // bin_s)
            if b in normal_set:
                fp_bins.add(b)
                any_alert_bins.add(b)

        res.detected = len(first_hit)
        res.latencies = [max(0.0, ts - type_incs[i].start) for i, ts in sorted(first_hit.items())]
        res.fp_bins = len(fp_bins)
        per_type[t] = res

    overall = TypeResult(alert_type="ALL")
    for r in per_type.values():
        overall.incidents += r.incidents
        overall.detected += r.detected
        overall.alerts += r.alerts
        overall.true_positives += r.true_positives
        overall.false_positives += r.false_positives
        overall.secondary += r.secondary
        overall.latencies += r.latencies
    overall.normal_bins = len(normal_bins)
    overall.fp_bins = len(any_alert_bins)
    return Score(per_type, overall, t_end - t_start, bin_s, grace_s)


def _match(ts: float, incidents: list[Incident], grace_s: float) -> Optional[int]:
    for i, inc in enumerate(incidents):
        if inc.start <= ts <= inc.end + grace_s:
            return i
    return None


def _median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def _r(v: Optional[float]) -> Optional[float]:
    return round(v, 4) if v is not None else None
