"""
GET   /alerts              — list alerts with optional filters
GET   /alerts/summary      — count by severity/type/status
GET   /alerts/{id}         — single alert detail (with explanation)
PATCH /alerts/{id}/status  — acknowledge or resolve an alert
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.api.state import anomaly_detector, db_writer
from backend.storage.database import persist_alert_status

router = APIRouter(tags=["alerts"])


class AlertStatusUpdate(BaseModel):
    status: str  # "ACTIVE" | "ACKNOWLEDGED" | "RESOLVED"


@router.get("/alerts")
def get_alerts(
    limit: int = Query(200, ge=1, le=2000),
    severity: Optional[str] = Query(None, description="LOW | MEDIUM | HIGH | CRITICAL"),
    alert_type: Optional[str] = Query(None, description="PORT_SCAN | SYN_FLOOD | ARP_ANOMALY | TRAFFIC_SPIKE"),
    status: Optional[str] = Query(None, description="ACTIVE | ACKNOWLEDGED | RESOLVED"),
):
    """Security / anomaly alerts, newest first.  All filters are optional."""
    alerts = anomaly_detector.get_alerts(
        limit=limit, severity=severity, alert_type=alert_type, status=status,
    )
    return {"count": len(alerts), "alerts": [a.to_dict() for a in alerts]}


@router.get("/alerts/summary")
def get_alerts_summary():
    """Alert counts grouped by severity, type and status."""
    all_alerts = anomaly_detector.get_alerts(limit=10_000)
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for a in all_alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1
    return {
        "total": len(all_alerts),
        "active": by_status.get("ACTIVE", 0),
        "by_severity": by_severity,
        "by_type": by_type,
        "by_status": by_status,
    }


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Full detail for a single alert, including its explanation."""
    alert = anomaly_detector.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, f"Alert '{alert_id}' not found.")
    return alert.to_dict()


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, body: AlertStatusUpdate):
    """Acknowledge, resolve or re-open an alert."""
    new_status = body.status.upper()
    if new_status not in ("ACTIVE", "ACKNOWLEDGED", "RESOLVED"):
        raise HTTPException(400, "Status must be 'ACTIVE', 'ACKNOWLEDGED' or 'RESOLVED'.")
    alert = anomaly_detector.set_status(alert_id, new_status)
    if alert is None:
        raise HTTPException(404, f"Alert '{alert_id}' not found.")
    db_writer.enqueue(persist_alert_status(alert_id, new_status))
    return {"alert_id": alert_id, "status": new_status}
