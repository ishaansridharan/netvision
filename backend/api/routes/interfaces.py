"""
GET  /interfaces          — list all network interfaces
POST /capture/start       — start packet capture
POST /capture/stop        — stop packet capture
GET  /capture/status      — current capture state
GET  /capture/npcap-check — Npcap availability check (Windows)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.capture.interface import list_interfaces, check_npcap, validate_interface
from backend.api.state import capture_engine

router = APIRouter(tags=["capture"])


class StartCaptureRequest(BaseModel):
    interface: str


@router.get("/interfaces")
def get_interfaces():
    """List all available network interfaces."""
    ifaces = list_interfaces()
    return {"interfaces": [i.to_dict() for i in ifaces]}


@router.get("/capture/npcap-check")
def npcap_check():
    """Check whether Npcap is installed (Windows only)."""
    return check_npcap()


@router.post("/capture/start")
def start_capture(body: StartCaptureRequest):
    """Start packet capture on the specified interface."""
    if capture_engine.is_running:
        raise HTTPException(
            status_code=409,
            detail=f"Capture already running on '{capture_engine.interface}'. Stop it first.",
        )

    if not validate_interface(body.interface):
        raise HTTPException(
            status_code=400,
            detail=f"Unknown interface '{body.interface}'. Call /interfaces to list valid names.",
        )

    npcap = check_npcap()
    if not npcap["available"]:
        raise HTTPException(status_code=503, detail=npcap["message"])

    try:
        capture_engine.start(body.interface)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"status": "started", "interface": body.interface}


@router.post("/capture/stop")
def stop_capture():
    """Stop the active packet capture."""
    if not capture_engine.is_running:
        raise HTTPException(status_code=409, detail="No capture is currently running.")
    capture_engine.stop()
    return {"status": "stopped"}


@router.get("/capture/status")
def capture_status():
    """Return current capture state."""
    return capture_engine.get_status()
