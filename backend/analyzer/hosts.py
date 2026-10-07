"""
NetVision — Host Registry (analyzer/hosts.py)

Keeps one record per IP address seen on the wire and answers the question
"which side of this packet is us?".

What it learns
──────────────
  • bytes / packets sent and received per host
  • MAC address (from ARP, or from Ethernet headers for on-link hosts)
  • hostnames (from observed DNS answers: "142.250.x.x is google.com")
  • whether the host is local (our machine), on the LAN, or external
  • which host is the default gateway

Direction classification
────────────────────────
A packet is UPLOAD if it leaves a local address for a non-local one,
DOWNLOAD if the reverse, and LAN if both ends are local.  "Local" means:
  1. one of the capture machine's own IPs (most precise), else
  2. inside a configured / interface-derived network, else
  3. an RFC 1918 private address (fallback used for pcap replay).

Memory bound
────────────
Spoofed-source floods can produce one "host" per packet, so the table is
an LRU capped at `max_tracked_hosts`.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from backend.parser.packet_parser import PacketRecord

logger = logging.getLogger(__name__)

UPLOAD, DOWNLOAD, LAN = "up", "down", "lan"


@dataclass
class HostInfo:
    ip: str
    first_seen: float
    last_seen: float
    mac: Optional[str] = None
    hostnames: list[str] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    scope: str = "external"        # "self" | "lan" | "external"
    is_gateway: bool = False

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def display_name(self) -> str:
        return self.hostnames[0] if self.hostnames else self.ip

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "name": self.display_name,
            "hostnames": self.hostnames,
            "mac": self.mac,
            "scope": self.scope,
            "is_gateway": self.is_gateway,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "total_bytes": self.total_bytes,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
        }


class HostRegistry:
    """LRU table of hosts plus local/remote classification."""

    _MAX_HOSTNAMES = 3

    def __init__(self, max_hosts: int = 20_000, local_networks: str = "") -> None:
        self._lock = threading.Lock()
        self._hosts: OrderedDict[str, HostInfo] = OrderedDict()
        self._max_hosts = max_hosts

        self._self_ips: set[str] = set()
        self._networks: list[ipaddress.IPv4Network] = _parse_networks(local_networks)
        self._configured_networks = bool(self._networks)
        self._gateway_ip: Optional[str] = None

        # Cache of ip → bool so we don't re-parse addresses per packet.
        self._local_cache: dict[str, bool] = {}

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #

    def configure_interface(
        self,
        self_ips: list[str],
        networks: list[str],
        gateway_ip: Optional[str] = None,
    ) -> None:
        """Called when capture starts on a real interface."""
        with self._lock:
            self._self_ips = set(self_ips)
            if not self._configured_networks:
                self._networks = _parse_networks(",".join(networks))
            self._gateway_ip = gateway_ip
            self._local_cache.clear()
            for host in self._hosts.values():
                host.scope = self._scope_of(host.ip)
                host.is_gateway = host.ip == gateway_ip
        logger.info(
            "Local addressing: self=%s networks=%s gateway=%s",
            sorted(self_ips), [str(n) for n in self._networks], gateway_ip,
        )

    @property
    def gateway_ip(self) -> Optional[str]:
        return self._gateway_ip

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #

    def is_local(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        cached = self._local_cache.get(ip)
        if cached is not None:
            return cached
        result = self._compute_is_local(ip)
        if len(self._local_cache) > 50_000:
            self._local_cache.clear()
        self._local_cache[ip] = result
        return result

    def _compute_is_local(self, ip: str) -> bool:
        if ip in self._self_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self._networks:
            return any(addr in net for net in self._networks)
        return addr.is_private and not addr.is_loopback

    def _scope_of(self, ip: str) -> str:
        if ip in self._self_ips:
            return "self"
        return "lan" if self.is_local(ip) else "external"

    def direction(self, pkt: PacketRecord) -> str:
        """Classify a packet as UPLOAD, DOWNLOAD or LAN."""
        if self._self_ips:
            if pkt.src_ip in self._self_ips and pkt.dst_ip not in self._self_ips:
                return UPLOAD
            if pkt.dst_ip in self._self_ips and pkt.src_ip not in self._self_ips:
                return DOWNLOAD
        src_local = self.is_local(pkt.src_ip)
        dst_local = self.is_local(pkt.dst_ip)
        if src_local and not dst_local:
            return UPLOAD
        if dst_local and not src_local:
            return DOWNLOAD
        return LAN

    # ------------------------------------------------------------------ #
    # Packet ingestion
    # ------------------------------------------------------------------ #

    def observe(self, pkt: PacketRecord) -> None:
        now = pkt.timestamp
        with self._lock:
            if pkt.protocol == "ARP":
                if pkt.arp_sender_ip and pkt.arp_sender_mac:
                    host = self._touch(pkt.arp_sender_ip, now)
                    host.mac = pkt.arp_sender_mac
                return

            if pkt.src_ip:
                src = self._touch(pkt.src_ip, now)
                src.bytes_sent += pkt.size
                src.packets_sent += 1
                # Ethernet source MAC only identifies on-link hosts; for
                # remote IPs it is the router's MAC.
                if pkt.src_mac and src.scope != "external" and not src.mac:
                    src.mac = pkt.src_mac
            if pkt.dst_ip:
                dst = self._touch(pkt.dst_ip, now)
                dst.bytes_recv += pkt.size
                dst.packets_recv += 1

            if pkt.dns_is_response and pkt.dns_query_name and pkt.dns_response_ips:
                for ip in pkt.dns_response_ips:
                    if ":" in ip:  # IPv6 answers — we only track IPv4 hosts
                        continue
                    host = self._touch(ip, now, count_as_seen=False)
                    names = host.hostnames
                    if pkt.dns_query_name in names:
                        continue
                    names.insert(0, pkt.dns_query_name)
                    del names[self._MAX_HOSTNAMES:]

    def _touch(self, ip: str, now: float, count_as_seen: bool = True) -> HostInfo:
        host = self._hosts.get(ip)
        if host is None:
            host = HostInfo(
                ip=ip, first_seen=now, last_seen=now,
                scope=self._scope_of(ip), is_gateway=(ip == self._gateway_ip),
            )
            self._hosts[ip] = host
            if len(self._hosts) > self._max_hosts:
                self._hosts.popitem(last=False)
        elif count_as_seen:
            self._hosts.move_to_end(ip)
        if count_as_seen:
            host.last_seen = max(host.last_seen, now)
        return host

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #

    def get(self, ip: str) -> Optional[HostInfo]:
        with self._lock:
            return self._hosts.get(ip)

    def name_of(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        host = self._hosts.get(ip)
        return host.display_name if host else ip

    def all_hosts(self) -> list[HostInfo]:
        with self._lock:
            return list(self._hosts.values())

    def count(self) -> int:
        return len(self._hosts)


def _parse_networks(spec: str) -> list[ipaddress.IPv4Network]:
    nets = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            logger.warning("Ignoring invalid network %r", part)
            continue
        if isinstance(net, ipaddress.IPv4Network) and not net.is_loopback:
            nets.append(net)
    return nets
