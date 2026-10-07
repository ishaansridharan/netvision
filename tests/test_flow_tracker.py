from backend.analyzer.flow_tracker import FlowTracker
from backend.parser.packet_parser import ACK, PSH, RST, SYN  # noqa: F401

from tests.helpers import cfg, handshake, tcp, udp

C, S = "10.0.0.5", "93.184.216.34"


def _run(tracker, pkts):
    return [tracker.process(p) for p in pkts]


def test_handshake_states_and_rtt():
    ft = FlowTracker(cfg())
    syn, synack, ack = handshake(100.0, C, S, 40000, 443, rtt=0.05)[:3]
    e1 = ft.process(syn)
    assert e1.is_new and e1.connection_attempt and e1.flow.tcp_state == "SYN_SENT"
    e2 = ft.process(synack)
    assert e2.flow.tcp_state == "SYN_RECEIVED" and e2.flow.is_half_open
    e3 = ft.process(ack)
    assert e3.flow.tcp_state == "ESTABLISHED" and e3.flow.handshake_completed
    # SYN→SYN-ACK (50 ms) + SYN-ACK→ACK (1 ms)
    assert abs(e3.rtt_sample_ms - 51.0) < 0.5
    assert e3.flow.src_ip == C and e3.flow.dst_port == 443


def test_close_with_fins():
    ft = FlowTracker(cfg())
    events = _run(ft, handshake(100.0, C, S, 40000, 443, data=500))
    assert events[-1].flow.tcp_state == "CLOSED"
    flow = events[-1].flow
    assert flow.fwd_packets == 3 and flow.bwd_packets == 3
    assert flow.bwd_bytes > flow.fwd_bytes   # server sent the data


def test_initiator_inferred_when_syn_missed():
    ft = FlowTracker(cfg())
    e = ft.process(tcp(1.0, S, C, 443, 40000, SYN | ACK))
    assert e.flow.src_ip == C and e.flow.dst_ip == S and e.flow.dst_port == 443
    assert not e.forward


def test_midstream_flow():
    ft = FlowTracker(cfg())
    e = ft.process(tcp(1.0, C, S, 40000, 443, PSH | ACK, seq=10, payload=100))
    assert e.flow.tcp_state == "ESTABLISHED" and e.flow.midstream
    assert not e.connection_attempt


def test_rst_marks_failed_attempt():
    ft = FlowTracker(cfg())
    ft.process(tcp(1.0, C, S, 40000, 81, SYN))
    e = ft.process(tcp(1.01, S, C, 81, 40000, RST | ACK))
    assert e.flow.tcp_state == "RESET" and not e.flow.handshake_completed


def test_port_reuse_after_reset_is_a_new_attempt():
    ft = FlowTracker(cfg())
    ft.process(tcp(1.0, C, S, 40000, 80, SYN))
    ft.process(tcp(1.01, S, C, 80, 40000, RST | ACK))
    e = ft.process(tcp(2.0, C, S, 40000, 80, SYN))
    assert e.connection_attempt and e.flow.tcp_state == "SYN_SENT"


def test_retransmission_detection_with_wraparound():
    ft = FlowTracker(cfg())
    near_wrap = 2**32 - 50
    e1 = ft.process(tcp(1.0, S, C, 443, 40000, PSH | ACK, seq=near_wrap, payload=100))
    e2 = ft.process(tcp(1.1, S, C, 443, 40000, PSH | ACK, seq=50, payload=100))   # wrapped, new data
    e3 = ft.process(tcp(1.2, S, C, 443, 40000, PSH | ACK, seq=50, payload=100))   # resent
    assert not e1.retransmission and not e2.retransmission
    assert e3.retransmission and e3.flow.retransmissions == 1


def test_state_aware_expiry():
    c = cfg(flow_half_open_timeout_s=5, flow_idle_timeout_s=60, flow_closed_linger_s=2)
    ft = FlowTracker(c)
    ft.process(tcp(0.0, C, S, 40001, 80, SYN))              # half-open
    _run(ft, handshake(0.0, C, S, 40002, 80))               # closed
    ft.process(udp(0.0, C, S, 5000, 53))                    # active UDP
    closed = []
    ft.add_close_callback(closed.append)
    assert ft.tick(3.0) == 1                                # closed linger passed
    assert ft.tick(6.0) == 1                                # half-open timeout passed
    assert ft.get_stats()["active_flows"] == 1
    assert ft.tick(61.0) == 1
    assert len(closed) == 3


def test_flow_cap_evicts_oldest():
    ft = FlowTracker(cfg(flow_max_active=10))
    for i in range(15):
        ft.process(udp(float(i), C, S, 10000 + i, 53))
    stats = ft.get_stats()
    assert stats["active_flows"] == 10 and stats["completed_flows"] == 5


def test_stats_count_half_open():
    ft = FlowTracker(cfg())
    ft.process(tcp(1.0, C, S, 40000, 80, SYN))
    _run(ft, handshake(1.0, C, S, 40001, 80)[:3])
    s = ft.get_stats()
    assert s["half_open_flows"] == 1
    assert s["tcp_states"] == {"SYN_SENT": 1, "ESTABLISHED": 1}
