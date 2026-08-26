"""
GET   /alerts              — list alerts with optional filters
GET   /alerts/{id}         — single alert detail
PATCH /alerts/{id}/status  — acknowledge or resolve an alert
GET   /alerts/summary      — count by severity/type
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.api.state import anomaly_detector

router = APIRouter(tags=["alerts"])


class AlertStatusUpdate(BaseModel):
    status: str  # "ACKNOWLEDGED" | "RESOLVED"


@router.get("/alerts")
def get_alerts(
    limit: int = Query(200, ge=1, le=2000),
    severity: Optional[str] = Query(None, description="LOW | MEDIUM | HIGH | CRITICAL"),
    alert_type: Optional[str] = Query(None, description="PORT_SCAN | SYN_FLOOD | ARP_ANOMALY | TRAFFIC_SPIKE"),
    status: Optional[str] = Query(None, description="ACTIVE | ACKNOWLEDGED | RESOLVED"),
):
    """
    Return security / anomaly alerts in descending timestamp order.
    All query parameters are optional filters.
    """
    alerts = anomaly_detector.get_alerts(
        limit=limit,
        severity=severity,
        alert_type=alert_type,
        status=status,
    )
    return {
        "count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


@router.get("/alerts/summary")
def get_alerts_summary():
    """Return alert counts grouped by severity and type."""
    all_alerts = anomaly_detector.get_alerts(limit=10_000)
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for a in all_alerts:
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_type[a.alert_type]   = by_type.get(a.alert_type, 0) + 1
        by_status[a.status]     = by_status.get(a.status, 0) + 1

    return {
        "total": len(all_alerts),
        "active": by_status.get("ACTIVE", 0),
        "by_severity": by_severity,
        "by_type": by_type,
        "by_status": by_status,
    }


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Return full detail for a single alert."""
    alerts = anomaly_detector.get_alerts(limit=10_000)
    for a in alerts:
        if a.alert_id == alert_id:
            return a.to_dict()
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")


@router.patch("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, body: AlertStatusUpdate):
    """Acknowledge or resolve an alert."""
    new_status = body.status.upper()
    if new_status not in ("ACKNOWLEDGED", "RESOLVED"):
        raise HTTPException(
            status_code=400,
            detail="Status must be 'ACKNOWLEDGED' or 'RESOLVED'.",
        )

    if new_status == "ACKNOWLEDGED":
        ok = anomaly_detector.acknowledge_alert(alert_id)
    else:
        ok = anomaly_detector.resolve_alert(alert_id)

    if not ok:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    return {"alert_id": alert_id, "status": new_status}
