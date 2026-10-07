from backend.pipeline import Pipeline
from backend.parser.packet_parser import ACK, PSH

from tests.helpers import cfg, handshake, icmp_echo, tcp

ME, SRV = "10.0.0.5", "93.184.216.34"


def _pipeline(**kw) -> Pipeline:
    p = Pipeline(cfg(**kw))
    p.hosts.configure_interface([ME], ["10.0.0.0/24"], "10.0.0.1")
    return p


def test_direction_and_bandwidth():
    p = _pipeline(stats_rolling_window_s=10)
    for i in range(10):
        p.process(tcp(100.0 + i, SRV, ME, 443, 40000, PSH | ACK, seq=i * 1000, payload=960))  # 1000 B down
        p.process(tcp(100.0 + i, ME, SRV, 40000, 443, PSH | ACK, seq=i * 60, payload=60))      # 100 B up
    snap, _ = p.tick(110.0)
    assert snap.download_bps == 1000.0
    assert snap.upload_bps == 100.0
    assert snap.lan_bps == 0.0
    assert snap.instant_bps == 1100.0
    assert snap.top_talkers[0]["ip"] == SRV and snap.top_talkers[0]["pct"] > 90


def test_icmp_rtt_matched_by_id_and_seq():
    p = _pipeline()
    # Two outstanding pings with different seq; replies arrive out of order.
    p.process(icmp_echo(10.000, ME, "1.1.1.1", reply=False, seq=1))
    p.process(icmp_echo(10.010, ME, "1.1.1.1", reply=False, seq=2))
    p.process(icmp_echo(10.040, "1.1.1.1", ME, reply=True, seq=2))   # 30 ms
    p.process(icmp_echo(10.050, "1.1.1.1", ME, reply=True, seq=1))   # 50 ms
    snap, _ = p.tick(11.0)
    assert snap.rtt_samples == 2
    assert abs(snap.latency_ms - 40.0) < 0.01
    assert abs(snap.jitter_ms - 20.0) < 0.01


def test_handshake_rtt_feeds_latency():
    p = _pipeline()
    for pkt in handshake(5.0, ME, SRV, 40000, 443, rtt=0.08):
        p.process(pkt)
    snap, _ = p.tick(6.0)
    assert snap.rtt_samples == 1 and 80 <= snap.latency_ms <= 82


def test_unknown_components_are_excluded_from_health():
    p = _pipeline()
    snap, _ = p.tick(1.0)
    comps = {c["name"]: c for c in snap.health["components"]}
    assert comps["latency"]["status"] == "unknown"
    assert comps["packet_loss"]["status"] == "unknown"
    assert snap.packet_loss_pct is None
    assert snap.health_score == 100     # only bandwidth + threats are known, both fine


def test_loss_estimate_from_retransmissions():
    p = _pipeline(loss_min_segments=20)
    seq = 0
    for i in range(40):
        p.process(tcp(50.0 + i * 0.01, SRV, ME, 443, 40000, PSH | ACK, seq=seq, payload=100))
        seq += 100
    for i in range(4):   # resend four earlier segments
        p.process(tcp(50.5 + i * 0.01, SRV, ME, 443, 40000, PSH | ACK, seq=i * 100, payload=100))
    snap, _ = p.tick(51.0)
    assert snap.retransmissions == 4
    assert abs(snap.packet_loss_pct - 4 / 44 * 100) < 0.01
    loss = next(c for c in snap.health["components"] if c["name"] == "packet_loss")
    assert loss["status"] == "bad"


def test_bandwidth_culprit_named_in_health():
    p = _pipeline(interface_capacity_mbps=1.0, stats_rolling_window_s=1)
    # ~120 kB in one second ≈ 0.96 Mbit/s on a 1 Mbit/s link
    for i in range(120):
        p.process(tcp(10.0 + i / 200, SRV, ME, 443, 40000, PSH | ACK, seq=i * 960, payload=960))
    snap, _ = p.tick(11.0)
    bw = next(c for c in snap.health["components"] if c["name"] == "bandwidth")
    assert bw["status"] == "bad"
    assert bw["culprit"]["ip"] == SRV
    assert snap.health["issues"] and SRV in snap.health["issues"][0]
