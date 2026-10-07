"""
NetVision — Shared Alert model (detection/models.py)

All detection modules produce Alert objects of this type.
The detector orchestrator collects them and passes them to storage + API.

Explainability
──────────────
Every alert carries an `explanation` built by `explain()`:

    {
      "summary":   plain-language sentence ("why did this fire?"),
      "metric":    what was measured,
      "observed":  the measured value,
      "threshold": the value it had to reach,
      "rule":      the decision rule in symbols,
      "baseline":  {mean, std, samples, scope} for adaptive decisions,
      "z_score":   how many σ above normal,
      "factors":   supporting evidence (list of strings),
    }

The dashboard renders this directly, so an operator never has to guess
why an alert exists.
"""

from __future__ import annotations

import itertools
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from backend.detection.baseline import BaselineView


SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_TYPES = ("PORT_SCAN", "SYN_FLOOD", "ARP_ANOMALY", "TRAFFIC_SPIKE")
ALERT_STATUSES = ("ACTIVE", "ACKNOWLEDGED", "RESOLVED")

_seq_counter = itertools.count(1)


@dataclass
class Alert:
    """Structured security / anomaly alert produced by a detection rule."""

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    seq: int = field(default_factory=lambda: next(_seq_counter))

    alert_type: str = "UNKNOWN"          # One of ALERT_TYPES
    severity: str = "MEDIUM"            # One of SEVERITY_LEVELS
    status: str = "ACTIVE"              # One of ALERT_STATUSES
    mode: str = "adaptive"              # Detection mode that produced it

    source_ip: Optional[str] = None
    target_ip: Optional[str] = None

    # Human-readable one-liner shown in the UI alert card
    description: str = ""

    # Structured evidence — type-specific fields
    evidence: dict[str, Any] = field(default_factory=dict)

    # Why the alert fired — see module docstring
    explanation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "status": self.status,
            "mode": self.mode,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "description": self.description,
            "evidence": self.evidence,
            "explanation": self.explanation,
        }


def explain(
    summary: str,
    metric: str,
    observed: float,
    threshold: float,
    rule: str,
    baseline: Optional[BaselineView] = None,
    z_score: Optional[float] = None,
    factors: Optional[list[str]] = None,
) -> dict[str, Any]:
    return {
        "summary": summary,
        "metric": metric,
        "observed": _round(observed),
        "threshold": _round(threshold),
        "rule": rule,
        "baseline": baseline.to_dict() if baseline else None,
        "z_score": round(z_score, 2) if z_score is not None else None,
        "factors": factors or [],
    }


def _round(v: float) -> float:
    return round(v, 3) if isinstance(v, float) else v
