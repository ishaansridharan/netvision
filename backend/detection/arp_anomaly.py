"""
NetVision — ARP Anomaly Detector (detection/arp_anomaly.py)

Detection logic
───────────────
ARP is used to resolve IP addresses to MAC addresses on a local network.

We maintain a trusted IP → MAC table populated from observed ARP REPLY
packets.  If we see an ARP reply that maps an IP to a *different* MAC
than previously recorded, we flag it as an ARP anomaly.

Why this matters
────────────────
ARP spoofing (ARP poisoning) is the basis of man-in-the-middle attacks
on local networks.  An attacker sends fake ARP replies to associate their
MAC address with a victim's IP (e.g., the default gateway), causing
traffic to flow through the attacker's machine.

Honesty about false positives
──────────────────────────────
• NIC replacement, VM migration, and DHCP lease changes are legitimate
  reasons for an IP → MAC mapping to change.
• We label this "ARP Anomaly" not "ARP Attack".
• We store the old and new MAC so the user can investigate.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

from backend.detection.models import Alert
from backend.parser.packet_parser import PacketRecord


class ArpAnomalyDetector:
    """
    Maintains a ground-truth ARP table and detects unexpected changes.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # ip → mac
        self._arp_table: dict[str, str] = {}
        # Cooldown per IP: ip → last alert time
        self._last_alert: dict[str, float] = {}
        self._cooldown_s: float = 60.0

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        """
        Inspect an ARP packet.  Returns an Alert if the IP→MAC mapping
        has changed unexpectedly, else None.

        Only ARP REPLY packets are used to build the table (requests are
        unreliable since the sender MAC could be spoofed too, but replies
        are what actually update the ARP cache).
        """
        if pkt.protocol != "ARP" or pkt.arp_op != "REPLY":
            return None

        sender_ip  = pkt.arp_sender_ip
        sender_mac = pkt.arp_sender_mac

        if not sender_ip or not sender_mac:
            return None

        # Ignore broadcast MACs
        if sender_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None

        now = time.time()

        with self._lock:
            existing_mac = self._arp_table.get(sender_ip)

            if existing_mac is None:
                # First time we see this IP — just record it
                self._arp_table[sender_ip] = sender_mac
                return None

            if existing_mac.lower() == sender_mac.lower():
                # Mapping unchanged — normal
                return None

            # Mapping changed — check cooldown
            last = self._last_alert.get(sender_ip, 0)
            if now - last < self._cooldown_s:
                return None

            old_mac = existing_mac
            self._arp_table[sender_ip] = sender_mac
            self._last_alert[sender_ip] = now

        return Alert(
            alert_type="ARP_ANOMALY",
            severity="MEDIUM",
            source_ip=pkt.src_mac,       # MAC of the sender
            target_ip=sender_ip,
            description=(
                f"ARP mapping changed for {sender_ip}: "
                f"{old_mac} → {sender_mac}. "
                f"Possible ARP spoofing or legitimate hardware change."
            ),
            evidence={
                "ip": sender_ip,
                "old_mac": old_mac,
                "new_mac": sender_mac,
                "arp_op": pkt.arp_op,
            },
        )

    def get_arp_table(self) -> dict[str, str]:
        """Return a snapshot of the current ARP table."""
        with self._lock:
            return dict(self._arp_table)
