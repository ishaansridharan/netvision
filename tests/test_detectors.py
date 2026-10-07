"""
Detector behaviour on in-memory traffic patterns, in both modes.

Each test pairs a pattern a detector must flag with a benign look-alike it
must stay quiet on, since false positives are what the adaptive mode is
meant to reduce.
"""

import pytest

from backend.parser.packet_parser import ACK, PSH, RST, SYN
from backend.pipeline import Pipeline

from tests.helpers import arp_reply, cfg, frame_from, handshake, tcp

LAN_HOST, TARGET = "10.0.0.66", "10.0.0.20"
MODES = ("static", "adaptive")


def _run(pipeline: Pipeline, pkts) -> list:
    return pipeline.run_offline(sorted(pkts, key=lambda p: p.timestamp))


def _types(alerts):
    return [a.alert_type for a in alerts]


# ── Port scan ──────────────────────────────────────────────────────────── #

def _many_port_attempts(t0: float, n_ports: int, rate: float) -> list:
    pkts = []
    for i in range(n_ports):
        t = t0 + i / rate
        port = 1000 + i
        pkts.append(tcp(t, LAN_HOST, TARGET, 50000, port, SYN))
        pkts.append(tcp(t + 0.001, TARGET, LAN_HOST, port, 50000, RST | ACK))
    return pkts


@pytest.mark.parametrize("mode", MODES)
def test_port_fan_out_is_flagged_with_explanation(mode):
    alerts = _run(Pipeline(cfg(), mode), _many_port_attempts(10.0, 100, rate=200))
    scans = [a for a in alerts if a.alert_type == "PORT_SCAN"]
    assert len(scans) == 1
    a = scans[0]
    assert a.mode == mode and a.source_ip == LAN_HOST and a.target_ip == TARGET
    assert a.severity == "HIGH"                       # nearly all attempts refused
    assert a.evidence["failed_ratio"] > 0.9
    assert a.explanation["observed"] >= a.explanation["threshold"]
    assert a.explanation["summary"]
    assert (a.explanation["baseline"] is not None) == (mode == "adaptive")


@pytest.mark.parametrize("mode", MODES)
def test_busy_server_replies_are_not_a_scan(mode):
    """A server answering 200 clients sends to 200 client ports — not a scan."""
    pkts = []
    for i in range(200):
        pkts += handshake(10.0 + i * 0.01, f"10.0.1.{i % 250}", TARGET, 30000 + i, 443)
    assert "PORT_SCAN" not in _types(_run(Pipeline(cfg(), mode), pkts))


def test_adaptive_learns_a_hosts_normal_fan_out():
    """
    A host that legitimately contacts ~12 ports every 5 s (above the static
    threshold of 15 only occasionally, above the adaptive floor of 8 always).
    After warm-up, adaptive mode treats that as normal for that host.
    """
    pkts = []
    for sec in range(120):
        for j in range(4):                     # ~20 distinct ports per 5 s window
            port = 2000 + (sec * 4 + j) % 40
            pkts += handshake(sec + j * 0.2, LAN_HOST, TARGET, 40000 + sec * 4 + j, port)
    static = _run(Pipeline(cfg(), "static"), pkts)
    adaptive = _run(Pipeline(cfg(), "adaptive"), pkts)
    n_static = _types(static).count("PORT_SCAN")
    n_adaptive = _types(adaptive).count("PORT_SCAN")
    assert n_static > 5
    assert n_adaptive < n_static / 2


# ── SYN flood ──────────────────────────────────────────────────────────── #

def _half_open_burst(t0: float, n: int, rate: float) -> list:
    pkts = []
    for i in range(n):
        t = t0 + i / rate
        src_port = 1024 + i % 60000
        pkts.append(tcp(t, f"10.9.{i % 200}.{i % 250}", TARGET, src_port, 80, SYN))
        pkts.append(tcp(t + 0.001, TARGET, f"10.9.{i % 200}.{i % 250}", 80, src_port, SYN | ACK))
    return pkts


@pytest.mark.parametrize("mode", MODES)
def test_half_open_syn_burst_is_flagged(mode):
    alerts = _run(Pipeline(cfg(), mode), _half_open_burst(10.0, 3000, rate=1000))
    floods = [a for a in alerts if a.alert_type == "SYN_FLOOD"]
    assert len(floods) == 1
    a = floods[0]
    assert a.target_ip == TARGET and a.evidence["incomplete_ratio"] > 0.9
    assert a.evidence["distinct_sources"] > 50
    assert a.timestamp - 10.0 < 2.0              # detection latency


@pytest.mark.parametrize("mode", MODES)
def test_busy_server_with_completed_handshakes_is_not_a_flood(mode):
    pkts = []
    for i in range(3000):
        pkts += handshake(10.0 + i / 300, f"10.0.2.{i % 250}", TARGET, 20000 + i, 443, rtt=0.01)
    assert "SYN_FLOOD" not in _types(_run(Pipeline(cfg(), mode), pkts))


# ── ARP ────────────────────────────────────────────────────────────────── #

GW, GW_MAC, OTHER_MAC = "10.0.0.1", "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02"


def _arp_change(old_mac_still_active: bool) -> list:
    pkts = [arp_reply(1.0, GW, GW_MAC)]
    if old_mac_still_active:
        pkts += [frame_from(1.0 + i, GW_MAC, src="8.8.8.8") for i in range(1, 30)]
    pkts.append(arp_reply(300.0 if not old_mac_still_active else 30.0, GW, OTHER_MAC))
    return pkts


def test_static_flags_any_mapping_change():
    alerts = _run(Pipeline(cfg(), "static"), _arp_change(old_mac_still_active=False))
    assert _types(alerts) == ["ARP_ANOMALY"]


def test_adaptive_treats_silent_old_mac_as_rebinding():
    p = Pipeline(cfg(), "adaptive")
    alerts = _run(p, _arp_change(old_mac_still_active=False))
    assert "ARP_ANOMALY" not in _types(alerts)
    assert p.detector.get_arp_rebindings()[0]["new_mac"] == OTHER_MAC


def test_adaptive_flags_conflicting_claim_on_gateway():
    p = Pipeline(cfg(), "adaptive")
    p.detector.set_gateway(GW)
    alerts = _run(p, _arp_change(old_mac_still_active=True))
    arp = [a for a in alerts if a.alert_type == "ARP_ANOMALY"]
    assert len(arp) == 1
    assert arp[0].severity == "HIGH"
    assert arp[0].evidence["old_mac"] == GW_MAC and arp[0].evidence["new_mac"] == OTHER_MAC
    assert any("gateway" in f for f in arp[0].explanation["factors"])


# ── Traffic spike ──────────────────────────────────────────────────────── #

def _throughput(seconds: range, bytes_per_s: int, start_seq: int = 0) -> list:
    pkts, seq = [], start_seq
    per_pkt = 1000
    for s in seconds:
        n = max(1, bytes_per_s // (per_pkt + 40))
        for i in range(n):
            pkts.append(tcp(s + i / n, "93.184.216.34", "10.0.0.5", 443, 40000,
                            PSH | ACK, seq=seq, payload=per_pkt))
            seq += per_pkt
    return pkts


def test_adaptive_spike_detected_relative_to_baseline():
    # 200 kB/s (1.6 Mbit/s) normal, then 5× for 6 s = 8 Mbit/s: unusual for
    # this network but still below the 10 Mbit/s static line.
    pkts = _throughput(range(0, 120), 200_000) + _throughput(range(120, 126), 1_000_000, 10**9)
    adaptive = _run(Pipeline(cfg(), "adaptive"), pkts)
    static = _run(Pipeline(cfg(), "static"), pkts)
    spikes = [a for a in adaptive if a.alert_type == "TRAFFIC_SPIKE"]
    assert len(spikes) == 1 and 121 <= spikes[0].timestamp <= 124
    assert spikes[0].explanation["baseline"]["mean"] < 300_000
    assert "TRAFFIC_SPIKE" not in _types(static)


def test_spike_needs_consecutive_seconds():
    pkts = _throughput(range(0, 60), 200_000) + _throughput(range(60, 61), 2_000_000, 10**9) \
        + _throughput(range(61, 70), 200_000, 2 * 10**9)
    assert "TRAFFIC_SPIKE" not in _types(_run(Pipeline(cfg(), "adaptive"), pkts))


def test_mode_switch_applies_to_every_detector():
    p = Pipeline(cfg(), "adaptive")
    p.detector.set_mode("static")
    alerts = _run(p, _many_port_attempts(10.0, 50, rate=100))
    assert alerts and all(a.mode == "static" for a in alerts)
    with pytest.raises(ValueError):
        p.detector.set_mode("magic")


def test_idle_ticks_do_not_teach_a_silent_baseline():
    """
    Unobserved time (no capture running) must not train the throughput
    baseline; otherwise traffic resuming after a pause looks like a spike.
    """
    p = Pipeline(cfg(), "adaptive")
    _run(p, _throughput(range(0, 60), 200_000))
    learned = p.detector.baseline_summary()["traffic_spike"]["population"]["mean"]
    for t in range(70, 400):                       # capture stopped for ~5 min
        p.tick(float(t), observing=False)
    after = p.detector.baseline_summary()["traffic_spike"]["population"]["mean"]
    assert after == learned
    resumed = _throughput(range(400, 430), 200_000, start_seq=10**9)
    assert "TRAFFIC_SPIKE" not in _types(p.run_offline(resumed))
