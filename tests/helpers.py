"""In-memory PacketRecord builders for tests.  Nothing here touches a network."""

from __future__ import annotations

import itertools
from typing import Optional

from backend.config import Settings
from backend.parser.packet_parser import ACK, FIN, PSH, RST, SYN, PacketRecord

_ids = itertools.count(1)

FLAG_NAMES = {SYN: "SYN", SYN | ACK: "SYN-ACK", ACK: "ACK", PSH | ACK: "PSH-ACK",
              FIN | ACK: "FIN-ACK", RST: "RST", RST | ACK: "RST-ACK"}


def tcp(ts: float, src: str, dst: str, sport: int, dport: int, flags: int,
        seq: int = 0, payload: int = 0, src_mac: Optional[str] = None) -> PacketRecord:
    return PacketRecord(
        id=str(next(_ids)), timestamp=ts, src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport, protocol="TCP", transport="TCP",
        tcp_flags=FLAG_NAMES.get(flags, str(flags)), tcp_flags_raw=flags,
        tcp_seq=seq, payload_len=payload, size=40 + payload, src_mac=src_mac,
    )


def udp(ts: float, src: str, dst: str, sport: int, dport: int, payload: int = 100) -> PacketRecord:
    return PacketRecord(
        id=str(next(_ids)), timestamp=ts, src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport, protocol="UDP", transport="UDP",
        payload_len=payload, size=28 + payload,
    )


def icmp_echo(ts: float, src: str, dst: str, reply: bool, ident: int = 1, seq: int = 1) -> PacketRecord:
    return PacketRecord(
        id=str(next(_ids)), timestamp=ts, src_ip=src, dst_ip=dst,
        protocol="ICMP", transport="ICMP", icmp_type=0 if reply else 8,
        icmp_id=ident, icmp_seq=seq, size=84,
    )


def arp_reply(ts: float, ip: str, mac: str, target_ip: str = "10.0.0.50") -> PacketRecord:
    return PacketRecord(
        id=str(next(_ids)), timestamp=ts, protocol="ARP", arp_op="REPLY",
        arp_sender_ip=ip, arp_sender_mac=mac, arp_target_ip=target_ip,
        src_ip=ip, dst_ip=target_ip, src_mac=mac, size=42,
    )


def frame_from(ts: float, mac: str, src: str = "10.0.0.1", dst: str = "10.0.0.50") -> PacketRecord:
    """Any frame sent by *mac* — proves that MAC is alive."""
    return PacketRecord(
        id=str(next(_ids)), timestamp=ts, src_ip=src, dst_ip=dst, src_mac=mac,
        protocol="UDP", transport="UDP", src_port=5000, dst_port=6000, size=128,
    )


def handshake(ts: float, client: str, server: str, cport: int, sport: int,
              rtt: float = 0.02, data: int = 0) -> list[PacketRecord]:
    """A complete, benign TCP connection: handshake, optional data, close."""
    pkts = [
        tcp(ts, client, server, cport, sport, SYN, seq=100),
        tcp(ts + rtt, server, client, sport, cport, SYN | ACK, seq=500),
        tcp(ts + rtt + 0.001, client, server, cport, sport, ACK, seq=101),
    ]
    t = ts + rtt + 0.002
    if data:
        pkts.append(tcp(t, server, client, sport, cport, PSH | ACK, seq=501, payload=data))
        t += 0.001
    pkts += [
        tcp(t, client, server, cport, sport, FIN | ACK, seq=101),
        tcp(t + rtt, server, client, sport, cport, FIN | ACK, seq=501 + data),
    ]
    return pkts


def cfg(**overrides) -> Settings:
    """Settings with test-friendly defaults (short warm-up)."""
    base = dict(baseline_warmup_samples=5, database_url="sqlite://")
    base.update(overrides)
    return Settings(**base)
