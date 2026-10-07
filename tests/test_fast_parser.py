"""The fast parser must agree with the Scapy reference parser field for field."""

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether

from backend.parser.fast_parser import (
    LINKTYPE_LINUX_SLL, LINKTYPE_RAW, parse_frame,
)
from backend.parser.packet_parser import parse_packet

_IGNORE = {"id", "seq"}

FRAMES = {
    "tcp_data": Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                TCP(sport=40000, dport=443, flags="PA", seq=7, ack=9, window=512) / (b"x" * 300),
    "tcp_syn_options": Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                       TCP(sport=1, dport=80, flags="S", options=[("MSS", 1460), ("WScale", 7)]),
    "udp": Ether() / IP() / UDP(sport=5000, dport=6000) / (b"y" * 64),
    "dns_query": Ether() / IP() / UDP(sport=33333, dport=53) /
                 DNS(id=5, rd=1, qd=DNSQR(qname="example.org", qtype="AAAA")),
    "dns_answer_compressed": Ether() / IP() / UDP(sport=53, dport=33333) /
                             DNS(id=5, qr=1, qd=DNSQR(qname="a.example.org"),
                                 an=DNSRR(rrname="a.example.org", type="A", rdata="1.2.3.4") /
                                 DNSRR(rrname="a.example.org", type="A", rdata="5.6.7.8")),
    "dns_tcp": Ether() / IP() / TCP(sport=40000, dport=53, flags="S"),
    "icmp_echo": Ether() / IP() / ICMP(type=8, id=9, seq=4),
    "icmp_unreachable": Ether() / IP() / ICMP(type=3, code=1) / IP() / TCP(),
    "arp_request": Ether() / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="aa:bb:cc:00:11:22"),
    "ip_options": Ether() / IP(options=b"\x94\x04\x00\x00") / TCP(sport=1, dport=2) / b"abc",
    "fragment_tail": Ether() / IP(frag=185, proto=6) / (b"z" * 40),
    "vlan": Ether() / Dot1Q(vlan=10) / IP(src="10.1.1.1", dst="10.1.1.2") / UDP(sport=1, dport=2),
}


@pytest.mark.parametrize("name", sorted(FRAMES))
def test_matches_scapy_reference(name):
    raw = bytes(FRAMES[name])
    ref_pkt = Ether(raw)
    ref_pkt.time = 1234.5
    ref = parse_packet(ref_pkt)
    fast = parse_frame(raw, 1234.5)
    assert (ref is None) == (fast is None)
    if ref is None:
        return
    a, b = fast.to_dict(), ref.to_dict()
    diff = {k: (a[k], b[k]) for k in a if k not in _IGNORE and a[k] != b[k]}
    assert not diff, diff


def test_ipv6_and_unknown_ethertypes_are_skipped():
    assert parse_frame(bytes(Ether() / IPv6() / UDP()), 0.0) is None
    assert parse_frame(bytes(Ether(type=0x88CC) / b"lldp"), 0.0) is None


def test_truncated_frames_do_not_raise():
    raw = bytes(Ether() / IP() / TCP())
    for cut in (5, 14, 20, 34, 40):
        parse_frame(raw[:cut], 0.0)   # must not raise


def test_raw_ip_and_linux_cooked_linktypes():
    ip = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2))
    r = parse_frame(ip, 1.0, LINKTYPE_RAW)
    assert r.src_ip == "10.0.0.1" and r.transport == "UDP"

    # SLL header: pkttype, arphrd, addr len 6, address (8 bytes), protocol 0x0800
    sll = (b"\x00\x00" + b"\x00\x01" + b"\x00\x06" + bytes.fromhex("aabbccddeeff") + b"\x00\x00"
           + b"\x08\x00")
    r = parse_frame(sll + ip, 1.0, LINKTYPE_LINUX_SLL)
    assert r.src_mac == "aa:bb:cc:dd:ee:ff" and r.dst_port == 2


def test_dns_pointer_loop_is_survived():
    # Header (1 question) then a name that points at itself.
    dns = b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    raw = bytes(Ether() / IP() / UDP(sport=53, dport=1)) + dns
    r = parse_frame(raw, 0.0)
    assert r is not None and r.protocol == "DNS"
