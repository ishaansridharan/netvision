"""
NetVision — Fast frame parser (parser/fast_parser.py)

Builds a PacketRecord directly from raw frame bytes with `struct`, without
creating Scapy packet objects.

Why
───
Scapy dissection costs ~150 µs per packet and reading fields back out of
the dissected object another ~60 µs, capping the system at roughly 4–5k
packets/s per core.  Decoding only the headers NetVision needs from bytes
is an order of magnitude cheaper.  Scapy is still used to *open* capture
sockets (Npcap on Windows, AF_PACKET on Linux) and to read pcap files; it
just no longer dissects every frame.

Contract
────────
`parse_frame()` produces the same PacketRecord as the Scapy-based
`packet_parser.parse_packet()` for the protocols NetVision handles; the
test-suite cross-checks the two on a capture file.

Link types handled: Ethernet (1, with 802.1Q/802.1ad VLAN tags), Linux
cooked v1/v2 (113/276), raw IPv4 (101/228/12), BSD loopback (0).
"""

from __future__ import annotations

import socket
import struct
import uuid
from typing import Optional

from backend.parser.packet_parser import (
    PacketRecord, _COMMON_FLAG_COMBOS, _DNS_QTYPES, _TCP_FLAG_BITS, _summarise,
)

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_BSD = 12
LINKTYPE_IPV4 = 228
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

_ETH_IPV4, _ETH_ARP, _ETH_VLAN, _ETH_QINQ = 0x0800, 0x0806, 0x8100, 0x88A8

_u16 = struct.Struct("!H").unpack_from
_eth = struct.Struct("!6s6sH").unpack_from
_ipv4 = struct.Struct("!BBHHHBBH4s4s").unpack_from
_tcp = struct.Struct("!HHIIBBH").unpack_from
_udp = struct.Struct("!HHH").unpack_from
_arp = struct.Struct("!HHBBH6s4s6s4s").unpack_from
_icmp_echo = struct.Struct("!HH").unpack_from
_dns_hdr = struct.Struct("!HHHHHH").unpack_from
_rr = struct.Struct("!HHIH").unpack_from

_ntoa = socket.inet_ntoa
_uuid4 = uuid.uuid4

# Flag-string cache: there are only 256 possible flag bytes.
_FLAG_CACHE: dict[int, str] = {}


def _flags_str(raw: int) -> str:
    s = _FLAG_CACHE.get(raw)
    if s is None:
        s = _COMMON_FLAG_COMBOS.get(raw)
        if s is None:
            parts = [name for bit, name in _TCP_FLAG_BITS.items() if raw & bit]
            s = "-".join(parts) if parts else "NONE"
        _FLAG_CACHE[raw] = s
    return s


def _mac(b: bytes) -> str:
    return b.hex(":")


def parse_frame(data: bytes, ts: float, linktype: int = LINKTYPE_ETHERNET) -> Optional[PacketRecord]:
    """Parse one captured frame.  Returns None for frames NetVision ignores."""
    try:
        return _parse(data, ts, linktype)
    except (struct.error, IndexError, ValueError):
        return None


def _parse(data: bytes, ts: float, linktype: int) -> Optional[PacketRecord]:
    rec = PacketRecord(id=str(_uuid4()), timestamp=ts)
    n = len(data)

    # ---- Link layer ------------------------------------------------------ #
    if linktype == LINKTYPE_ETHERNET:
        dst, src, etype = _eth(data, 0)
        rec.dst_mac, rec.src_mac = _mac(dst), _mac(src)
        rec.size = n
        off = 14
        while etype in (_ETH_VLAN, _ETH_QINQ):
            etype = _u16(data, off + 2)[0]
            off += 4
    elif linktype == LINKTYPE_LINUX_SLL:
        alen = _u16(data, 4)[0]
        if alen == 6:
            rec.src_mac = _mac(data[6:12])
        etype = _u16(data, 14)[0]
        off = 16
    elif linktype == LINKTYPE_LINUX_SLL2:
        etype = _u16(data, 0)[0]
        if data[11] == 6:
            rec.src_mac = _mac(data[12:18])
        off = 20
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_RAW_BSD):
        if n < 1 or data[0] >> 4 != 4:
            return None
        etype, off = _ETH_IPV4, 0
    elif linktype == LINKTYPE_NULL:
        family = struct.unpack_from("=I", data, 0)[0]
        if family != socket.AF_INET:
            return None
        etype, off = _ETH_IPV4, 4
    else:
        return None

    # ---- ARP --------------------------------------------------------------- #
    if etype == _ETH_ARP:
        _, ptype, hlen, plen, op, sha, spa, tha, tpa = _arp(data, off)
        if hlen != 6 or plen != 4:
            return None
        rec.protocol = "ARP"
        rec.size = n
        rec.arp_op = "REQUEST" if op == 1 else "REPLY" if op == 2 else str(op)
        rec.arp_sender_mac = _mac(sha)
        rec.arp_sender_ip = _ntoa(spa)
        rec.arp_target_mac = _mac(tha)
        rec.arp_target_ip = _ntoa(tpa)
        rec.src_ip, rec.dst_ip = rec.arp_sender_ip, rec.arp_target_ip
        rec.raw_summary = _summarise(rec)
        return rec

    if etype != _ETH_IPV4:
        return None

    # ---- IPv4 -------------------------------------------------------------- #
    vihl, _tos, total_len, _id, frag, ttl, proto, _csum, src, dst = _ipv4(data, off)
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    rec.src_ip, rec.dst_ip = _ntoa(src), _ntoa(dst)
    rec.ttl = ttl
    rec.size = total_len if total_len else n
    l4 = off + ihl
    if frag & 0x1FFF:          # non-first fragment: no transport header
        rec.raw_summary = _summarise(rec)
        return rec

    # ---- ICMP -------------------------------------------------------------- #
    if proto == 1:
        rec.protocol = rec.transport = "ICMP"
        rec.icmp_type, rec.icmp_code = data[l4], data[l4 + 1]
        if rec.icmp_type in (0, 8):
            rec.icmp_id, rec.icmp_seq = _icmp_echo(data, l4 + 4)
        rec.raw_summary = _summarise(rec)
        return rec

    # ---- TCP --------------------------------------------------------------- #
    if proto == 6:
        sport, dport, seq, ack, doff, flags, window = _tcp(data, l4)
        hdr = (doff >> 4) * 4
        rec.transport = "TCP"
        rec.src_port, rec.dst_port = sport, dport
        rec.tcp_seq, rec.tcp_ack, rec.tcp_window = seq, ack, window
        rec.tcp_flags_raw = flags
        rec.tcp_flags = _flags_str(flags)
        if total_len:
            rec.payload_len = max(0, total_len - ihl - hdr)
        else:
            rec.payload_len = max(0, n - l4 - hdr)
        if sport == 53 or dport == 53:
            rec.protocol = "DNS"
            # DNS over TCP carries a 2-byte length prefix
            start = l4 + hdr + 2
            if rec.payload_len > 2 and start < n:
                _parse_dns(data, start, rec)
        else:
            rec.protocol = "TCP"
        rec.raw_summary = _summarise(rec)
        return rec

    # ---- UDP --------------------------------------------------------------- #
    if proto == 17:
        sport, dport, ulen = _udp(data, l4)
        rec.transport = "UDP"
        rec.src_port, rec.dst_port = sport, dport
        rec.payload_len = max(0, ulen - 8) if ulen else max(0, n - l4 - 8)
        if sport == 53 or dport == 53:
            rec.protocol = "DNS"
            if l4 + 8 < n:
                _parse_dns(data, l4 + 8, rec)
        else:
            rec.protocol = "UDP"
        rec.raw_summary = _summarise(rec)
        return rec

    rec.raw_summary = _summarise(rec)
    return rec


# ──────────────────────────────────────────────────────────────────────────
# DNS (best effort — never raises)
# ──────────────────────────────────────────────────────────────────────────

def _read_name(data: bytes, pos: int, base: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; returns (name, next_pos)."""
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            pos = base + ptr
            hops += 1
            if hops > 20:
                raise ValueError("DNS pointer loop")
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    return ".".join(labels), (end if end is not None else pos)


def _parse_dns(data: bytes, base: int, rec: PacketRecord) -> None:
    try:
        _id, flags, qd, an, _ns, _ar = _dns_hdr(data, base)
        rec.dns_is_response = bool(flags & 0x8000)
        pos = base + 12
        if qd:
            name, pos = _read_name(data, pos, base)
            qtype = _u16(data, pos)[0]
            pos += 4
            rec.dns_query_name = name
            rec.dns_query_type = _DNS_QTYPES.get(qtype, str(qtype))
            for _ in range(qd - 1):
                _, pos = _read_name(data, pos, base)
                pos += 4
        if rec.dns_is_response and an:
            ips: list[str] = []
            for _ in range(an):
                _, pos = _read_name(data, pos, base)
                rtype, _cls, _ttl, rdlen = _rr(data, pos)
                pos += 10
                if rtype == 1 and rdlen == 4:
                    ips.append(_ntoa(data[pos:pos + 4]))
                elif rtype == 28 and rdlen == 16:
                    ips.append(socket.inet_ntop(socket.AF_INET6, data[pos:pos + 16]))
                pos += rdlen
            rec.dns_response_ips = ips
    except (struct.error, IndexError, ValueError, UnicodeDecodeError):
        pass


# ──────────────────────────────────────────────────────────────────────────
# Link-type helpers for live sockets
# ──────────────────────────────────────────────────────────────────────────

_LL_BY_NAME = {
    "Ether": LINKTYPE_ETHERNET,
    "CookedLinux": LINKTYPE_LINUX_SLL,
    "CookedLinuxV2": LINKTYPE_LINUX_SLL2,
    "IP": LINKTYPE_RAW,
    "Loopback": LINKTYPE_NULL,
}


def linktype_of(ll_class) -> int:
    """Map the Scapy layer class a socket reports to a pcap link type."""
    name = getattr(ll_class, "__name__", "")
    return _LL_BY_NAME.get(name, LINKTYPE_ETHERNET)
