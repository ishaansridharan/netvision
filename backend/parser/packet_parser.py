"""
NetVision — Packet Parser (parser/packet_parser.py)

Converts a raw Scapy packet object into a clean, typed PacketRecord.

Layers handled
──────────────
  Layer 2  : Ethernet (src/dst MAC)
  Layer 2  : ARP (op, sender/target IP+MAC)
  Layer 3  : IP  (src/dst IP, TTL, total length, protocol number)
  Layer 3  : ICMP (type, code, echo id/seq)
  Layer 4  : TCP (src/dst port, flags, seq, ack, window, payload length)
  Layer 4  : UDP (src/dst port, length)
  App      : DNS (query name, query type, response IPs)

Design decisions
────────────────
- Returns None for packets we cannot sensibly parse (no IP/ARP/Ethernet).
- DNS detection: if UDP port 53 or TCP port 53, attempt DNS layer parse.
- `protocol` is the display protocol (DNS wins over TCP/UDP), while
  `transport` is always the real L4 protocol.  Anything that needs TCP
  semantics (flow state, SYN flood) must check `transport`, otherwise
  DNS-over-TCP would be silently skipped.
- TCP flags stored as a human-readable string: "SYN", "ACK", "SYN-ACK",
  "FIN", "RST", "FIN-ACK", "PSH-ACK", etc. — not a bitmask.
- The summary string is built from parsed fields; Scapy's .summary() costs
  ~30 µs per packet, a large share of the per-packet budget.
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

    # Monotonic sequence number assigned by the capture engine.  Lets API
    # clients ask for "packets since N" without timestamp ambiguity.
    seq: int = 0

    # Layer 2 — Ethernet
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    # Layer 3 — IP
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    protocol: str = "OTHER"         # "TCP","UDP","ICMP","ARP","DNS","OTHER"
    transport: Optional[str] = None  # "TCP" | "UDP" | "ICMP" | None

    # Layer 4 — TCP / UDP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP-specific
    tcp_flags: Optional[str] = None   # Human-readable: "SYN", "ACK", …
    tcp_flags_raw: Optional[int] = None  # Original bitmask for detectors
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None

    # Application payload bytes carried by this segment (TCP/UDP)
    payload_len: int = 0

    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    icmp_id: Optional[int] = None
    icmp_seq: Optional[int] = None

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

    # Short human-readable summary
    raw_summary: str = ""

    # ------------------------------------------------------------------ #
    # TCP flag helpers (bitmask based, so combos like PSH-ACK work)
    # ------------------------------------------------------------------ #

    @property
    def is_tcp(self) -> bool:
        return self.transport == "TCP"

    def has_flag(self, bit: int) -> bool:
        return bool(self.tcp_flags_raw and self.tcp_flags_raw & bit)

    @property
    def is_syn(self) -> bool:
        """Pure SYN (connection attempt), not SYN-ACK."""
        return self.is_tcp and self.has_flag(SYN) and not self.has_flag(ACK)

    @property
    def is_syn_ack(self) -> bool:
        return self.is_tcp and self.has_flag(SYN) and self.has_flag(ACK)

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON responses."""
        return {
            "id": self.id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "transport": self.transport,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "tcp_window": self.tcp_window,
            "payload_len": self.payload_len,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "icmp_id": self.icmp_id,
            "icmp_seq": self.icmp_seq,
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

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

# Scapy stores TCP flags as a FlagValue object.
# We convert to an integer bitmask and then to a readable string.
_TCP_FLAG_BITS = {
    FIN: "FIN",
    SYN: "SYN",
    RST: "RST",
    PSH: "PSH",
    ACK: "ACK",
    URG: "URG",
    ECE: "ECE",
    CWR: "CWR",
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
    (e.g., raw 802.11 management frames, IPv6-only traffic, pure noise).
    """
    record = PacketRecord(
        id=str(uuid.uuid4()),
        timestamp=float(getattr(raw_pkt, "time", time.time())),
    )

    # ---- Layer 2 : Ethernet ------------------------------------------ #
    _parse_ethernet(raw_pkt, record)

    # ---- Layer 2 : ARP ------------------------------------------------ #
    if _has_layer(raw_pkt, "ARP"):
        _parse_arp(raw_pkt, record)
        record.raw_summary = _summarise(record)
        return record

    # ---- Layer 3 : IP ------------------------------------------------- #
    if _has_layer(raw_pkt, "IP"):
        _parse_ip(raw_pkt, record)
    else:
        # No IP and no ARP — not useful for our purposes
        return None

    # ---- Layer 3 : ICMP ----------------------------------------------- #
    # ICMP error messages embed the offending IP/TCP header; checking ICMP
    # first stops us from mistaking that inner header for real TCP traffic.
    if _has_layer(raw_pkt, "ICMP"):
        _parse_icmp(raw_pkt, record)
        record.raw_summary = _summarise(record)
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

    record.raw_summary = _summarise(record)
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
    record.transport = "ICMP"
    record.icmp_type = int(icmp.type) if icmp.type is not None else None
    record.icmp_code = int(icmp.code) if icmp.code is not None else None

    # Echo request/reply carry an identifier and sequence number, which is
    # what lets us pair a reply with the exact request for RTT measurement.
    if record.icmp_type in (0, 8):
        record.icmp_id  = int(getattr(icmp, "id", 0) or 0)
        record.icmp_seq = int(getattr(icmp, "seq", 0) or 0)


def _parse_tcp(pkt, record: PacketRecord) -> None:
    tcp = _get_layer(pkt, "TCP")
    if tcp is None:
        return

    record.transport = "TCP"
    record.src_port = int(tcp.sport) if tcp.sport is not None else None
    record.dst_port = int(tcp.dport) if tcp.dport is not None else None
    record.tcp_seq  = int(tcp.seq)   if tcp.seq   is not None else None
    record.tcp_ack  = int(tcp.ack)   if tcp.ack   is not None else None
    record.tcp_window = int(tcp.window) if tcp.window is not None else None

    flags_str, flags_raw = _decode_tcp_flags(tcp.flags)
    record.tcp_flags     = flags_str
    record.tcp_flags_raw = flags_raw

    # Payload length from header arithmetic rather than len(payload): the
    # capture may be truncated (snaplen) but the IP length is authoritative.
    ip = _get_layer(pkt, "IP")
    try:
        if ip is not None and ip.len:
            record.payload_len = max(
                0, int(ip.len) - int(ip.ihl) * 4 - int(tcp.dataofs) * 4
            )
        else:
            record.payload_len = len(tcp.payload)
    except Exception:
        record.payload_len = 0

    # Classify as DNS if on port 53, otherwise TCP
    if record.src_port == 53 or record.dst_port == 53:
        record.protocol = "DNS"
    else:
        record.protocol = "TCP"


def _parse_udp(pkt, record: PacketRecord) -> None:
    udp = _get_layer(pkt, "UDP")
    if udp is None:
        return

    record.transport = "UDP"
    record.src_port = int(udp.sport) if udp.sport is not None else None
    record.dst_port = int(udp.dport) if udp.dport is not None else None
    try:
        record.payload_len = max(0, int(udp.len) - 8) if udp.len else len(udp.payload)
    except Exception:
        record.payload_len = 0

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

        # Query section (Scapy ≥2.6 exposes qd as a list)
        qd = getattr(dns, "qd", None)
        if isinstance(qd, list):
            qd = qd[0] if qd else None
        if qd is not None:
            raw_name = getattr(qd, "qname", None)
            if raw_name:
                if isinstance(raw_name, bytes):
                    raw_name = raw_name.decode("utf-8", errors="replace")
                record.dns_query_name = str(raw_name).rstrip(".")
            qtype = getattr(qd, "qtype", None)
            if qtype is not None:
                record.dns_query_type = _dns_qtype_name(int(qtype))

        # Answer section — collect A/AAAA response IPs
        if record.dns_is_response:
            answers = getattr(dns, "an", None)
            ips: list[str] = []
            if isinstance(answers, list):
                rrs = answers
            else:
                # Older Scapy: answers are chained via .payload
                rrs = []
                while answers is not None and hasattr(answers, "rdata"):
                    rrs.append(answers)
                    answers = getattr(answers, "payload", None)
            for rr in rrs:
                if getattr(rr, "type", None) in (1, 28):  # A / AAAA
                    rdata = getattr(rr, "rdata", None)
                    if rdata:
                        ips.append(str(rdata))
            record.dns_response_ips = ips

    except Exception:
        # DNS parsing is best-effort — never crash the main pipeline
        pass


def _summarise(r: PacketRecord) -> str:
    """Build a one-line, Wireshark-style summary from parsed fields."""
    if r.protocol == "ARP":
        if r.arp_op == "REQUEST":
            return f"ARP who-has {r.arp_target_ip} tell {r.arp_sender_ip}"
        return f"ARP {r.arp_sender_ip} is-at {r.arp_sender_mac}"
    if r.transport == "ICMP":
        kind = {0: "echo-reply", 8: "echo-request", 3: "dest-unreachable",
                11: "time-exceeded"}.get(r.icmp_type, f"type={r.icmp_type}")
        return f"ICMP {r.src_ip} > {r.dst_ip} {kind}"
    if r.protocol == "DNS" and r.dns_query_name:
        kind = "response" if r.dns_is_response else "query"
        return f"DNS {kind} {r.dns_query_type or ''} {r.dns_query_name}".strip()
    if r.transport in ("TCP", "UDP"):
        flags = f" [{r.tcp_flags}]" if r.tcp_flags else ""
        return (f"{r.transport} {r.src_ip}:{r.src_port} > "
                f"{r.dst_ip}:{r.dst_port}{flags} len={r.payload_len}")
    return f"IP {r.src_ip} > {r.dst_ip}"
