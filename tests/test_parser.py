"""Parser tests on Scapy packets built in memory."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from backend.parser.packet_parser import parse_packet


def _roundtrip(pkt):
    """Serialise and re-dissect, as a real capture would."""
    return Ether(bytes(pkt))


def test_tcp_fields_and_payload_length():
    raw = _roundtrip(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                     TCP(sport=40000, dport=443, flags="PA", seq=1000) / (b"x" * 120))
    r = parse_packet(raw)
    assert r.protocol == "TCP" and r.transport == "TCP"
    assert (r.src_port, r.dst_port) == (40000, 443)
    assert r.tcp_flags == "PSH-ACK"
    assert r.payload_len == 120
    assert r.size == 20 + 20 + 120
    assert "10.0.0.1:40000 > 10.0.0.2:443" in r.raw_summary


def test_syn_helpers():
    r = parse_packet(_roundtrip(Ether() / IP() / TCP(flags="S")))
    assert r.is_syn and not r.is_syn_ack
    r = parse_packet(_roundtrip(Ether() / IP() / TCP(flags="SA")))
    assert r.is_syn_ack and not r.is_syn


def test_dns_over_tcp_keeps_tcp_transport():
    r = parse_packet(_roundtrip(Ether() / IP() / TCP(sport=5555, dport=53, flags="S")))
    assert r.protocol == "DNS"
    assert r.transport == "TCP"    # flow/SYN logic must still see it as TCP


def test_dns_response_answers():
    dns = DNS(id=1, qr=1, qd=DNSQR(qname="example.com", qtype="A"),
              an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"))
    r = parse_packet(_roundtrip(Ether() / IP(src="8.8.8.8", dst="10.0.0.2") /
                                UDP(sport=53, dport=33333) / dns))
    assert r.protocol == "DNS" and r.transport == "UDP"
    assert r.dns_is_response
    assert r.dns_query_name == "example.com"
    assert r.dns_query_type == "A"
    assert r.dns_response_ips == ["93.184.216.34"]


def test_icmp_echo_id_and_seq():
    r = parse_packet(_roundtrip(Ether() / IP() / ICMP(type=8, id=77, seq=3)))
    assert r.transport == "ICMP"
    assert (r.icmp_type, r.icmp_id, r.icmp_seq) == (8, 77, 3)


def test_icmp_error_is_not_mistaken_for_tcp():
    inner = IP(src="10.0.0.2", dst="10.0.0.9") / TCP(sport=1, dport=2, flags="S")
    r = parse_packet(_roundtrip(Ether() / IP(src="10.0.0.9", dst="10.0.0.2") /
                                ICMP(type=3, code=3) / inner))
    assert r.protocol == "ICMP"
    assert r.tcp_flags is None


def test_arp_reply():
    r = parse_packet(_roundtrip(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:ff",
                                              pdst="10.0.0.2")))
    assert r.protocol == "ARP" and r.arp_op == "REPLY"
    assert (r.arp_sender_ip, r.arp_sender_mac) == ("10.0.0.1", "aa:bb:cc:dd:ee:ff")


def test_non_ip_frames_are_skipped():
    assert parse_packet(Ether(type=0x88cc) / b"lldp") is None
