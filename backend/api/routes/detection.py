"""
GET /detection/config     — current mode and every threshold in use
PUT /detection/mode       — switch between "static" and "adaptive"
GET /detection/baselines  — live adaptive baselines (μ, σ, current threshold)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.api.state import anomaly_detector
from backend.config import settings

router = APIRouter(tags=["detection"])


class ModeUpdate(BaseModel):
    mode: str


@router.get("/detection/config")
def detection_config():
    s = settings
    return {
        "mode": anomaly_detector.mode,
        "adaptive": {
            "baseline_alpha": s.baseline_alpha,
            "z_threshold": s.baseline_z_threshold,
            "warmup_samples": s.baseline_warmup_samples,
        },
        "port_scan": {
            "window_s": s.port_scan_window_s,
            "static_threshold_ports": s.port_scan_threshold,
            "adaptive_floor_ports": s.port_scan_adaptive_floor,
            "cooldown_s": s.port_scan_cooldown_s,
        },
        "syn_flood": {
            "window_s": s.syn_flood_window_s,
            "static_syn_threshold": s.syn_flood_syn_threshold,
            "static_incomplete_ratio": s.syn_flood_incomplete_ratio,
            "adaptive_rate_window_s": s.syn_flood_rate_window_s,
            "adaptive_floor_rate": s.syn_flood_adaptive_floor_rate,
            "adaptive_min_ratio": s.syn_flood_adaptive_min_ratio,
            "cooldown_s": s.syn_flood_cooldown_s,
        },
        "arp": {
            "conflict_window_s": s.arp_conflict_window_s,
            "cooldown_s": s.arp_cooldown_s,
        },
        "traffic_spike": {
            "static_threshold_bps": s.traffic_spike_static_bps,
            "adaptive_multiplier": s.traffic_spike_multiplier,
            "adaptive_min_bps": s.traffic_spike_min_bps,
            "min_duration_s": s.traffic_spike_min_duration_s,
            "cooldown_s": s.traffic_spike_cooldown_s,
        },
    }


@router.put("/detection/mode")
def set_detection_mode(body: ModeUpdate):
    """Switch detection mode at runtime.  Baselines keep learning in both modes."""
    mode = body.mode.lower()
    try:
        anomaly_detector.set_mode(mode)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"mode": anomaly_detector.mode}


@router.get("/detection/baselines")
def detection_baselines():
    """Current adaptive baselines — what 'normal' looks like right now."""
    return anomaly_detector.baseline_summary()
