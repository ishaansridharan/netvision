"""
NetVision — Packet Parser (parser/packet_parser.py)

Converts a raw Scapy packet object into a clean, typed PacketRecord.

Layers handled
──────────────
  Layer 2  : Ethernet (src/dst MAC)
  Layer 2  : ARP (op, sender/target IP+MAC)
  Layer 3  : IP  (src/dst IP, TTL, total length, protocol number)
  Layer 3  : ICMP (type, code)
  Layer 4  : TCP (src/dst port, flags, seq, ack, window)
  Layer 4  : UDP (src/dst port, length)
  App      : DNS (query name, query type, response IPs)

Design decisions
────────────────
- Returns None for packets we cannot sensibly parse (no IP/ARP/Ethernet).
- DNS detection: if UDP port 53 or TCP port 53, attempt DNS layer parse.
- TCP flags stored as a human-readable string: "SYN", "ACK", "SYN-ACK",
  "FIN", "RST", "FIN-ACK", "PSH-ACK", etc. — not a bitmask.
- All optional fields default to None — the consumer must handle None.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────
# Normalised packet data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class PacketRecord:
    """
    The single, canonical representation of a captured packet in NetVision.
    Every downstream module (flow tracker, stats engine, detector) works
    with this type — never with raw Scapy objects.
    """

    # Identity
    id: str                         # UUID4 string
    timestamp: float                # Unix epoch (seconds, float)

    # Layer 2 — Ethernet
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    # Layer 3 — IP
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    protocol: str = "OTHER"         # "TCP","UDP","ICMP","ARP","DNS","OTHER"

    # Layer 4 — TCP / UDP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP-specific
    tcp_flags: Optional[str] = None   # Human-readable: "SYN", "ACK", …
    tcp_flags_raw: Optional[int] = None  # Original bitmask for detectors
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None

    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # ARP
    arp_op: Optional[str] = None      # "REQUEST" | "REPLY"
    arp_sender_mac: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None

    # DNS
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[str] = None   # "A", "AAAA", "MX", "PTR", …
    dns_response_ips: list[str] = field(default_factory=list)
    dns_is_response: bool = False

    # Size in bytes (IP total length, or Ethernet frame length as fallback)
    size: int = 0

    # Short human-readable summary (Scapy's .summary() for quick debugging)
    raw_summary: str = ""

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON responses."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "tcp_window": self.tcp_window,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "arp_op": self.arp_op,
            "arp_sender_mac": self.arp_sender_mac,
            "arp_sender_ip": self.arp_sender_ip,
            "arp_target_mac": self.arp_target_mac,
            "arp_target_ip": self.arp_target_ip,
            "dns_query_name": self.dns_query_name,
            "dns_query_type": self.dns_query_type,
            "dns_response_ips": self.dns_response_ips,
            "dns_is_response": self.dns_is_response,
            "size": self.size,
            "raw_summary": self.raw_summary,
        }


# ──────────────────────────────────────────────────────────────────────────
# TCP flag decoding
# ──────────────────────────────────────────────────────────────────────────

# Scapy stores TCP flags as a FlagValue object.
# We convert to an integer bitmask and then to a readable string.
_TCP_FLAG_BITS = {
    0x001: "FIN",
    0x002: "SYN",
    0x004: "RST",
    0x008: "PSH",
    0x010: "ACK",
    0x020: "URG",
    0x040: "ECE",
    0x080: "CWR",
}

# Common combined flag strings for readability
_COMMON_FLAG_COMBOS: dict[int, str] = {
    0x002: "SYN",
    0x010: "ACK",
    0x012: "SYN-ACK",
    0x011: "FIN-ACK",
    0x004: "RST",
    0x014: "RST-ACK",
    0x018: "PSH-ACK",
    0x019: "FIN-PSH-ACK",
    0x001: "FIN",
}


def _decode_tcp_flags(flags) -> tuple[str, int]:
    """
    Convert Scapy's TCP flags to (human_string, raw_int).
    Returns ("", 0) on failure.
    """
    try:
        raw = int(flags)
    except (TypeError, ValueError):
        return "", 0

    label = _COMMON_FLAG_COMBOS.get(raw)
    if label:
        return label, raw

    # Fall back to concatenating individual flag names
    parts = [name for bit, name in _TCP_FLAG_BITS.items() if raw & bit]
    return "-".join(parts) if parts else "NONE", raw


# ──────────────────────────────────────────────────────────────────────────
# DNS query type decoding
# ──────────────────────────────────────────────────────────────────────────

_DNS_QTYPES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _dns_qtype_name(qtype: int) -> str:
    return _DNS_QTYPES.get(qtype, str(qtype))


# ──────────────────────────────────────────────────────────────────────────
# Main parser entry point
# ──────────────────────────────────────────────────────────────────────────

def parse_packet(raw_pkt) -> Optional[PacketRecord]:
    """
    Parse a raw Scapy packet into a PacketRecord.

    Returns None for packets that have no useful network-layer information
    (e.g., raw 802.11 management frames, pure noise).
    """
    record = PacketRecord(
        id=str(uuid.uuid4()),
        timestamp=float(getattr(raw_pkt, "time", time.time())),
        raw_summary=raw_pkt.summary() if hasattr(raw_pkt, "summary") else "",
    )

    # ---- Layer 2 : Ethernet ------------------------------------------ #
    _parse_ethernet(raw_pkt, record)

    # ---- Layer 2 : ARP ------------------------------------------------ #
    if _has_layer(raw_pkt, "ARP"):
        _parse_arp(raw_pkt, record)
        return record

    # ---- Layer 3 : IP ------------------------------------------------- #
    if _has_layer(raw_pkt, "IP"):
        _parse_ip(raw_pkt, record)
    else:
        # No IP and no ARP — not useful for our purposes
        return None

    # ---- Layer 3 : ICMP ----------------------------------------------- #
    if _has_layer(raw_pkt, "ICMP"):
        _parse_icmp(raw_pkt, record)
        return record

    # ---- Layer 4 : TCP ------------------------------------------------ #
    if _has_layer(raw_pkt, "TCP"):
        _parse_tcp(raw_pkt, record)

    # ---- Layer 4 : UDP ------------------------------------------------ #
    elif _has_layer(raw_pkt, "UDP"):
        _parse_udp(raw_pkt, record)

    # ---- Application : DNS (over UDP/TCP port 53) --------------------- #
    if record.src_port == 53 or record.dst_port == 53:
        _parse_dns(raw_pkt, record)

    return record


# ──────────────────────────────────────────────────────────────────────────
# Layer-specific parsers
# ──────────────────────────────────────────────────────────────────────────

def _has_layer(pkt, layer_name: str) -> bool:
    """Check if a Scapy packet contains a given layer by name string."""
    try:
        return pkt.haslayer(layer_name)
    except Exception:
        return False


def _get_layer(pkt, layer_name: str):
    """Return the named layer or None."""
    try:
        return pkt.getlayer(layer_name) if pkt.haslayer(layer_name) else None
    except Exception:
        return None


def _parse_ethernet(pkt, record: PacketRecord) -> None:
    eth = _get_layer(pkt, "Ether")
    if eth is None:
        return
    record.src_mac = str(eth.src) if eth.src else None
    record.dst_mac = str(eth.dst) if eth.dst else None
    record.size = len(pkt)  # Ethernet frame size as fallback


def _parse_arp(pkt, record: PacketRecord) -> None:
    arp = _get_layer(pkt, "ARP")
    if arp is None:
        return

    record.protocol = "ARP"
    record.size = len(pkt)

    op = getattr(arp, "op", None)
    if op == 1:
        record.arp_op = "REQUEST"
    elif op == 2:
        record.arp_op = "REPLY"
    else:
        record.arp_op = str(op) if op is not None else None

    record.arp_sender_mac = str(arp.hwsrc) if getattr(arp, "hwsrc", None) else None
    record.arp_sender_ip  = str(arp.psrc)  if getattr(arp, "psrc",  None) else None
    record.arp_target_mac = str(arp.hwdst) if getattr(arp, "hwdst", None) else None
    record.arp_target_ip  = str(arp.pdst)  if getattr(arp, "pdst",  None) else None

    # Also populate src/dst IP for consistency
    record.src_ip = record.arp_sender_ip
    record.dst_ip = record.arp_target_ip


def _parse_ip(pkt, record: PacketRecord) -> None:
    ip = _get_layer(pkt, "IP")
    if ip is None:
        return

    record.src_ip = str(ip.src) if ip.src else None
    record.dst_ip = str(ip.dst) if ip.dst else None
    record.ttl    = int(ip.ttl) if ip.ttl is not None else None

    # IP total length is more accurate than frame size for traffic accounting
    if ip.len:
        record.size = int(ip.len)
    else:
        record.size = len(pkt)


def _parse_icmp(pkt, record: PacketRecord) -> None:
    icmp = _get_layer(pkt, "ICMP")
    if icmp is None:
        return

    record.protocol  = "ICMP"
    record.icmp_type = int(icmp.type) if icmp.type is not None else None
    record.icmp_code = int(icmp.code) if icmp.code is not None else None


def _parse_tcp(pkt, record: PacketRecord) -> None:
    tcp = _get_layer(pkt, "TCP")
    if tcp is None:
        return

    record.src_port = int(tcp.sport) if tcp.sport is not None else None
    record.dst_port = int(tcp.dport) if tcp.dport is not None else None
    record.tcp_seq  = int(tcp.seq)   if tcp.seq   is not None else None
    record.tcp_ack  = int(tcp.ack)   if tcp.ack   is not None else None
    record.tcp_window = int(tcp.window) if tcp.window is not None else None

    flags_str, flags_raw = _decode_tcp_flags(tcp.flags)
    record.tcp_flags     = flags_str
    record.tcp_flags_raw = flags_raw

    # Classify as DNS if on port 53, otherwise TCP
    if record.src_port == 53 or record.dst_port == 53:
        record.protocol = "DNS"
    else:
        record.protocol = "TCP"


def _parse_udp(pkt, record: PacketRecord) -> None:
    udp = _get_layer(pkt, "UDP")
    if udp is None:
        return

    record.src_port = int(udp.sport) if udp.sport is not None else None
    record.dst_port = int(udp.dport) if udp.dport is not None else None

    if record.src_port == 53 or record.dst_port == 53:
        record.protocol = "DNS"
    else:
        record.protocol = "UDP"


def _parse_dns(pkt, record: PacketRecord) -> None:
    """
    Attempt to extract DNS query / response information.
    Scapy's DNS layer may not always be present (e.g. MDNS, LLMNR).
    We catch all exceptions to avoid crashing the parser.
    """
    try:
        dns = _get_layer(pkt, "DNS")
        if dns is None:
            return

        record.protocol = "DNS"
        record.dns_is_response = bool(getattr(dns, "qr", 0))

        # Query section
        qd = getattr(dns, "qd", None)
        if qd is not None:
            raw_name = getattr(qd, "qname", None)
            if raw_name:
                name = raw_name.decode("utf-8", errors="replace").rstrip(".")
                record.dns_query_name = name
            qtype = getattr(qd, "qtype", None)
            if qtype is not None:
                record.dns_query_type = _dns_qtype_name(int(qtype))

        # Answer section — collect A/AAAA response IPs
        if record.dns_is_response:
            an = getattr(dns, "an", None)
            ips: list[str] = []
            while an is not None:
                rdata = getattr(an, "rdata", None)
                if rdata:
                    ips.append(str(rdata))
                an = getattr(an, "payload", None)
                # Stop when we hit a Raw/NoPayload layer
                if an and not hasattr(an, "rdata"):
                    break
            record.dns_response_ips = ips

    except Exception:
        # DNS parsing is best-effort — never crash the main pipeline
        pass
