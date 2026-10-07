"""API smoke + replay through the real server stack (no privileges needed)."""

import importlib
import time

import pytest
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("CAPTURES_DIR", str(tmp_path / "captures"))
    monkeypatch.setenv("STATS_SNAPSHOT_INTERVAL_S", "0.2")
    import backend.config
    import backend.storage.database
    import backend.api.state
    import backend.main
    for mod in (backend.config, backend.storage.database, backend.api.state):
        importlib.reload(mod)
    for name in ("alerts", "detection", "flows", "health", "interfaces",
                 "packets", "reports", "stats", "topology"):
        importlib.reload(importlib.import_module(f"backend.api.routes.{name}"))
    importlib.reload(importlib.import_module("backend.api.websocket"))
    importlib.reload(backend.main)
    from fastapi.testclient import TestClient
    with TestClient(backend.main.app) as c:
        yield c


def _write_capture(dir_):
    dir_.mkdir(parents=True, exist_ok=True)
    pkts = []
    t = 1_000.0
    for i in range(40):
        sport = 41000 + i
        for p in (Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=sport, dport=443, flags="S"),
                  Ether() / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=443, dport=sport, flags="SA"),
                  Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=sport, dport=443, flags="A")):
            p.time = t
            pkts.append(p)
            t += 0.01
    ping = Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8, id=1, seq=1)
    ping.time = t
    pkts.append(ping)
    wrpcap(str(dir_ / "demo.pcap"), pkts)


def test_replay_populates_every_view(client, tmp_path):
    _write_capture(tmp_path / "captures")
    files = client.get("/capture/files").json()["files"]
    assert [f["name"] for f in files] == ["demo.pcap"]

    r = client.post("/capture/replay", json={"file": "demo.pcap", "speed": 0})
    assert r.status_code == 200, r.text
    deadline = time.time() + 10
    while time.time() < deadline and client.get("/capture/status").json()["total_packets"] < 121:
        time.sleep(0.1)
    time.sleep(0.5)   # let a snapshot tick happen

    assert client.get("/capture/status").json()["total_packets"] == 121
    assert client.get("/packets?limit=5&protocol=TCP").json()["count"] == 5
    assert client.get("/flows/stats").json()["tcp_states"] == {"ESTABLISHED": 40}
    snap = client.get("/stats/current").json()["snapshot"]
    assert snap["rtt_samples"] >= 40 and snap["latency_ms"] is not None
    topo = client.get("/topology").json()
    assert {n["ip"] for n in topo["nodes"]} >= {"192.168.1.10", "93.184.216.34"}
    assert client.get("/metrics/pipeline").json()["processed"] == 121
    assert client.get("/reports/diagnosis").json()["now"]["health_score"] is not None


def test_replay_rejects_paths(client):
    r = client.post("/capture/replay", json={"file": "../../etc/passwd"})
    assert r.status_code == 400


def test_alert_status_and_mode_switch(client):
    assert client.put("/detection/mode", json={"mode": "static"}).json() == {"mode": "static"}
    assert client.get("/detection/config").json()["mode"] == "static"
    assert client.put("/detection/mode", json={"mode": "nope"}).status_code == 400
    assert client.patch("/alerts/missing/status", json={"status": "RESOLVED"}).status_code == 404


def test_websocket_pushes_updates(client):
    with client.websocket_connect("/ws/live") as ws:
        ws.send_text('{"packet_limit": 10}')
        msg = ws.receive_json()
        assert msg["type"] == "live_update"
        assert {"packets", "stats", "new_alerts", "capture", "pipeline"} <= set(msg)
