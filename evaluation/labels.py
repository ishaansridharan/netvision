"""
Ground-truth labels for a capture (evaluation/labels.py)

A labels file sits next to its capture (`lab1.pcap` → `lab1.labels.json`):

    {
      "description": "Lab run 1 — mixed normal traffic with three scenarios",
      "time_base": "absolute",          // or "relative" (seconds from first packet)
      "network": {                      // optional: helps upload/download + ARP
        "self_ips": ["10.10.0.5"],
        "local_networks": ["10.10.0.0/24"],
        "gateway": "10.10.0.1"
      },
      "incidents": [
        {"type": "PORT_SCAN", "start": 1791380000.0, "end": 1791380040.0,
         "source": "10.10.0.66", "target": "10.10.0.20", "note": "scan scenario"}
      ]
    }

Incident types are the alert types: PORT_SCAN, SYN_FLOOD, ARP_ANOMALY,
TRAFFIC_SPIKE.  Everything outside an incident window is treated as normal
traffic, so label every scenario you run — including legitimate events you
expect a detector might wrongly flag (leave those *unlabelled*: they are
exactly the false positives the comparison should count).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Optional

from evaluation.metrics import ALERT_TYPES, Incident


def labels_path_for(pcap_path: str) -> str:
    stem, _ = os.path.splitext(pcap_path)
    return stem + ".labels.json"


def load_labels(path: str, first_packet_ts: Optional[float] = None) -> dict:
    with open(path) as fh:
        data = json.load(fh)
    offset = 0.0
    if data.get("time_base", "absolute") == "relative":
        if first_packet_ts is None:
            raise ValueError("Relative labels need the capture's first packet timestamp.")
        offset = first_packet_ts

    incidents = []
    for raw in data.get("incidents", []):
        t = raw["type"].upper()
        if t not in ALERT_TYPES:
            raise ValueError(f"Unknown incident type {raw['type']!r}; expected one of {ALERT_TYPES}")
        if raw.get("end") is None:
            raise ValueError(f"Incident {t} starting at {raw['start']} has no end time.")
        incidents.append(Incident(
            type=t,
            start=float(raw["start"]) + offset,
            end=float(raw["end"]) + offset,
            source=raw.get("source"),
            target=raw.get("target"),
            note=raw.get("note", ""),
        ))
    incidents.sort(key=lambda i: i.start)
    return {
        "description": data.get("description", ""),
        "network": data.get("network", {}),
        "incidents": incidents,
    }


def incidents_to_json(incidents: list[Incident]) -> list[dict]:
    return [asdict(i) for i in incidents]
