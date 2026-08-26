"""
NetVision — Shared Alert model (detection/models.py)

All detection modules produce Alert objects of this type.
The detector orchestrator collects them and passes them to storage + API.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_TYPES = ("PORT_SCAN", "SYN_FLOOD", "ARP_ANOMALY", "TRAFFIC_SPIKE")
ALERT_STATUSES = ("ACTIVE", "ACKNOWLEDGED", "RESOLVED")


@dataclass
class Alert:
    """Structured security / anomaly alert produced by a detection rule."""

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    alert_type: str = "UNKNOWN"          # One of ALERT_TYPES
    severity: str = "MEDIUM"            # One of SEVERITY_LEVELS
    status: str = "ACTIVE"              # One of ALERT_STATUSES

    source_ip: Optional[str] = None
    target_ip: Optional[str] = None

    # Human-readable one-liner shown in the UI alert card
    description: str = ""

    # Structured evidence — type-specific fields
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "status": self.status,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "description": self.description,
            "evidence": self.evidence,
        }
