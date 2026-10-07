"""
GET  /interfaces            — list all network interfaces
GET  /capture/npcap-check   — Npcap availability check (Windows)
POST /capture/start         — start live packet capture
POST /capture/replay        — replay a pcap file from the captures directory
GET  /capture/files         — pcap files available for replay
POST /capture/stop          — stop the current capture source
GET  /capture/status        — current capture state
"""

from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.api.state import (
    anomaly_detector, capture_engine, configure_for_interface, host_registry,
)
from backend.capture.engine import CaptureError
from backend.capture.interface import (
    check_npcap, get_default_interface, list_interfaces, validate_interface,
)
from backend.config import settings

router = APIRouter(tags=["capture"])


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = Field(None, description="Interface name; default = best guess")
    bpf_filter: Optional[str] = Field(None, description="Optional BPF filter, e.g. 'tcp or arp'")


class ReplayRequest(BaseModel):
    file: str = Field(..., description="File name inside the captures directory")
    speed: float = Field(1.0, ge=0.0, le=100.0, description="Playback speed; 0 = as fast as possible")
    loop: bool = False


@router.get("/interfaces")
def get_interfaces():
    """List all available network interfaces."""
    ifaces = list_interfaces()
    return {
        "interfaces": [i.to_dict() for i in ifaces],
        "default": get_default_interface(),
    }


@router.get("/capture/npcap-check")
def npcap_check():
    """Check whether Npcap is installed (Windows only)."""
    return check_npcap()


@router.post("/capture/start")
def start_capture(body: StartCaptureRequest):
    """Start live packet capture on the specified (or default) interface."""
    if capture_engine.is_running:
        raise HTTPException(409, f"Capture already running ({capture_engine.describe_source()}). Stop it first.")

    interface = body.interface or get_default_interface()
    if not interface or not validate_interface(interface):
        raise HTTPException(400, f"Unknown interface '{interface}'. Call /interfaces to list valid names.")

    npcap = check_npcap()
    if not npcap["available"]:
        raise HTTPException(503, npcap["message"])

    network = configure_for_interface(interface)
    try:
        capture_engine.start(interface, bpf_filter=body.bpf_filter or None)
    except CaptureError as exc:
        raise HTTPException(503, str(exc))

    return {"status": "started", "interface": interface, "network": network}


def _captures_dir() -> str:
    return os.path.abspath(settings.captures_dir)


@router.get("/capture/files")
def list_capture_files():
    """List .pcap / .pcapng files that can be replayed."""
    root = _captures_dir()
    if not os.path.isdir(root):
        return {"directory": root, "files": []}
    files = []
    for name in sorted(os.listdir(root)):
        if name.lower().endswith((".pcap", ".pcapng", ".cap")):
            path = os.path.join(root, name)
            files.append({"name": name, "size_bytes": os.path.getsize(path)})
    return {"directory": root, "files": files}


@router.post("/capture/replay")
def replay_capture(body: ReplayRequest):
    """Replay a recorded capture through the live pipeline (no privileges needed)."""
    if capture_engine.is_running:
        raise HTTPException(409, f"Capture already running ({capture_engine.describe_source()}). Stop it first.")

    # Only bare file names inside the captures directory are accepted.
    name = os.path.basename(body.file)
    if name != body.file or name in ("", ".", ".."):
        raise HTTPException(400, "Provide a file name from /capture/files, not a path.")
    path = os.path.join(_captures_dir(), name)

    network = _labels_network(path)
    if network:
        host_registry.configure_interface(
            network.get("self_ips", []), network.get("local_networks", []), network.get("gateway"))
        anomaly_detector.set_gateway(network.get("gateway"))

    try:
        capture_engine.start_replay(path, speed=body.speed, loop=body.loop)
    except CaptureError as exc:
        raise HTTPException(400, str(exc))
    return {"status": "replaying", "file": name, "speed": body.speed, "loop": body.loop,
            "network": network}


def _labels_network(pcap_path: str) -> Optional[dict]:
    """Addressing hints from a `<capture>.labels.json` next to the file, if any."""
    labels = os.path.splitext(pcap_path)[0] + ".labels.json"
    try:
        with open(labels) as fh:
            net = json.load(fh).get("network") or None
    except (OSError, ValueError):
        return None
    return net if isinstance(net, dict) else None


@router.post("/capture/stop")
def stop_capture():
    """Stop the active capture source."""
    if not capture_engine.is_running:
        raise HTTPException(409, "No capture is currently running.")
    capture_engine.stop()
    return {"status": "stopped"}


@router.get("/capture/status")
def capture_status():
    """Return current capture state."""
    return capture_engine.get_status()
