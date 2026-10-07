"""
GET /topology        — nodes and edges for the Network Map view
GET /hosts           — host table (traffic, names, MACs)
GET /hosts/{ip}      — one host, with its flows
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Query

from backend.api.state import anomaly_detector, flow_tracker, host_registry

router = APIRouter(tags=["topology"])


@router.get("/topology")
def get_topology(
    max_nodes: int = Query(60, ge=5, le=500),
    window_s: float = Query(300.0, ge=10, le=86_400, description="Only hosts/flows seen this recently"),
):
    """
    "Who is communicating with whom?"

    Nodes are hosts (role: self / gateway / lan / external) sized by traffic.
    Edges aggregate every flow between a pair of hosts in the window, with
    bytes in each direction, packets, flow count and protocols.
    """
    now = time.time()
    cutoff = now - window_s

    flows = [f for f in flow_tracker.get_all_flows(limit=20_000) if f.last_seen >= cutoff]

    edges: dict[tuple[str, str], dict] = {}
    node_bytes: dict[str, int] = defaultdict(int)
    for f in flows:
        a, b = f.src_ip, f.dst_ip
        key = (a, b) if a <= b else (b, a)
        e = edges.get(key)
        if e is None:
            e = edges[key] = {
                "source": key[0], "target": key[1], "bytes": 0,
                "bytes_ab": 0, "bytes_ba": 0, "packets": 0, "flows": 0,
                "active_flows": 0, "protocols": set(), "ports": set(),
                "last_seen": 0.0,
            }
        a_to_b = (a == key[0])
        e["bytes"] += f.total_bytes
        e["bytes_ab"] += f.fwd_bytes if a_to_b else f.bwd_bytes
        e["bytes_ba"] += f.bwd_bytes if a_to_b else f.fwd_bytes
        e["packets"] += f.total_packets
        e["flows"] += 1
        if f.tcp_state not in ("CLOSED", "RESET"):
            e["active_flows"] += 1
        e["protocols"].add(f.protocol)
        if f.dst_port is not None and len(e["ports"]) < 10:
            e["ports"].add(f.dst_port)
        e["last_seen"] = max(e["last_seen"], f.last_seen)
        node_bytes[a] += f.total_bytes
        node_bytes[b] += f.total_bytes

    gateway = host_registry.gateway_ip
    hosts = {h.ip: h for h in host_registry.all_hosts() if h.last_seen >= cutoff}
    for ip in node_bytes:
        hosts.setdefault(ip, None)

    # Keep the busiest nodes, but always keep our own addresses and the gateway.
    pinned = {ip for ip, h in hosts.items() if h and (h.scope == "self" or h.is_gateway)}
    ranked = sorted(hosts, key=lambda ip: -node_bytes.get(ip, 0))
    keep = set(list(pinned) + [ip for ip in ranked if ip not in pinned][: max(0, max_nodes - len(pinned))])

    arp = anomaly_detector.get_arp_table()
    nodes = []
    for ip in keep:
        h = hosts.get(ip)
        role = "external"
        if h is not None:
            role = "gateway" if h.is_gateway or ip == gateway else (
                "self" if h.scope == "self" else h.scope)
        nodes.append({
            "id": ip,
            "ip": ip,
            "name": h.display_name if h else ip,
            "hostnames": h.hostnames if h else [],
            "mac": (h.mac if h else None) or arp.get(ip),
            "role": role,
            "bytes": node_bytes.get(ip, 0),
            "bytes_sent": h.bytes_sent if h else 0,
            "bytes_recv": h.bytes_recv if h else 0,
            "last_seen": h.last_seen if h else None,
        })

    edge_list = []
    for e in edges.values():
        if e["source"] in keep and e["target"] in keep:
            e["protocols"] = sorted(e["protocols"])
            e["ports"] = sorted(e["ports"])
            edge_list.append(e)
    edge_list.sort(key=lambda e: -e["bytes"])

    return {
        "generated_at": now,
        "window_s": window_s,
        "gateway": gateway,
        "nodes": sorted(nodes, key=lambda n: -n["bytes"]),
        "edges": edge_list,
        "truncated": len(hosts) > len(keep),
        "total_hosts": len(hosts),
    }


@router.get("/hosts")
def get_hosts(
    limit: int = Query(100, ge=1, le=5000),
    scope: str | None = Query(None, description="self | lan | external"),
):
    hosts = host_registry.all_hosts()
    if scope:
        hosts = [h for h in hosts if h.scope == scope]
    hosts.sort(key=lambda h: -h.total_bytes)
    return {"count": len(hosts), "hosts": [h.to_dict() for h in hosts[:limit]]}


@router.get("/hosts/{ip}")
def get_host(ip: str):
    host = host_registry.get(ip)
    if host is None:
        raise HTTPException(404, f"Host '{ip}' not seen.")
    flows = [f for f in flow_tracker.get_all_flows(limit=5_000) if ip in (f.src_ip, f.dst_ip)]
    flows.sort(key=lambda f: -f.total_bytes)
    alerts = [
        a.to_dict() for a in anomaly_detector.get_alerts(limit=2_000)
        if ip in (a.source_ip, a.target_ip)
    ][:20]
    return {
        **host.to_dict(),
        "flows": [f.to_dict() for f in flows[:50]],
        "alerts": alerts,
    }
