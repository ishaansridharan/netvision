"""
NetVision — ARP Anomaly Detector (detection/arp_anomaly.py)

ARP resolves IP addresses to MAC addresses on a local network.  We keep an
IP → MAC table learned from the sender fields of ARP requests and replies
(both update a host's ARP cache), optionally seeded from the OS ARP cache
at capture start.

Why this matters
────────────────
ARP spoofing (ARP poisoning) is the basis of man-in-the-middle attacks on
local networks.  An attacker sends forged ARP replies associating their MAC
with a victim's IP (typically the default gateway), so traffic flows
through the attacker's machine.

Static mode
───────────
Any change of an IP's MAC raises an alert.  This is the textbook rule, but
DHCP re-assignment, a replaced NIC or a VM moving hosts all change mappings
legitimately and all produce false positives.

Adaptive mode — conflict vs. re-binding
───────────────────────────────────────
The key question is whether the *old* MAC is still alive:

  • Conflict: the previous MAC was seen sending frames within
    `arp_conflict_window_s`.  Two live devices claim the same IP —
    the signature of spoofing (the real gateway keeps forwarding traffic
    while the attacker claims its IP).  → alert
  • Flip-flop: the IP has changed MAC ≥ 2 times in 10 minutes.  → alert
  • Re-binding: the old MAC has gone silent.  The device left and the IP
    was re-assigned.  → recorded, no alert

Severity is raised to HIGH when the IP is the default gateway, when the
mapping flip-flops, or when the new MAC claims several IPs at once.

Honesty about false positives
─────────────────────────────
We label this "ARP Anomaly", not "ARP Attack", and store the old and new
MAC so the user can investigate.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from typing import Optional

from backend.analyzer.flow_tracker import FlowEvent
from backend.config import Settings, settings as default_settings
from backend.detection.models import Alert, explain
from backend.parser.packet_parser import PacketRecord

_IGNORED_MACS = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
_FLIP_WINDOW_S = 600.0
_MAX_MACS = 20_000


class ArpAnomalyDetector:
    """Maintains an IP→MAC table and detects suspicious changes."""

    def __init__(self, cfg: Settings = default_settings, mode: str = "adaptive") -> None:
        self._cfg = cfg
        self.mode = mode
        self._arp_table: dict[str, str] = {}
        # MAC → last time any frame was sent from it (LRU-bounded)
        self._mac_last_seen: OrderedDict[str, float] = OrderedDict()
        # IP → recent (ts, old_mac, new_mac) changes
        self._changes: dict[str, deque] = {}
        # MAC → IPs it has claimed via ARP
        self._claims: dict[str, set[str]] = {}
        self._last_alert: dict[str, float] = {}
        self.gateway_ip: Optional[str] = None
        self.rebindings: deque[dict] = deque(maxlen=200)

    def seed(self, table: dict[str, str]) -> None:
        """Pre-load trusted mappings (e.g. the OS ARP cache)."""
        for ip, mac in table.items():
            mac = mac.lower()
            if mac not in _IGNORED_MACS:
                self._arp_table.setdefault(ip, mac)

    # ------------------------------------------------------------------ #
    # Per packet
    # ------------------------------------------------------------------ #

    def process(self, pkt: PacketRecord, event: Optional[FlowEvent] = None) -> Optional[Alert]:
        now = pkt.timestamp

        # Liveness of every MAC — needed to tell conflicts from re-bindings.
        # Recorded *after* the change check so the claiming frame itself
        # doesn't count as evidence the old MAC is alive.
        src_mac = pkt.src_mac.lower() if pkt.src_mac else None

        alert = None
        if pkt.protocol == "ARP":
            alert = self._process_arp(pkt, now)

        if src_mac and src_mac not in _IGNORED_MACS:
            self._mac_last_seen[src_mac] = now
            self._mac_last_seen.move_to_end(src_mac)
            if len(self._mac_last_seen) > _MAX_MACS:
                self._mac_last_seen.popitem(last=False)
        return alert

    def _process_arp(self, pkt: PacketRecord, now: float) -> Optional[Alert]:
        ip = pkt.arp_sender_ip
        mac = pkt.arp_sender_mac.lower() if pkt.arp_sender_mac else None
        if not ip or not mac or ip == "0.0.0.0" or mac in _IGNORED_MACS:
            return None

        self._claims.setdefault(mac, set()).add(ip)

        old_mac = self._arp_table.get(ip)
        if old_mac is None:
            self._arp_table[ip] = mac
            return None
        if old_mac == mac:
            return None

        # Mapping changed
        self._arp_table[ip] = mac
        changes = self._changes.setdefault(ip, deque(maxlen=50))
        changes.append((now, old_mac, mac))
        while changes and changes[0][0] < now - _FLIP_WINDOW_S:
            changes.popleft()
        flips = len(changes)

        old_last = self._mac_last_seen.get(old_mac)
        old_idle = (now - old_last) if old_last is not None else None
        old_alive = old_idle is not None and old_idle <= self._cfg.arp_conflict_window_s
        claimed_ips = sorted(self._claims.get(mac, ()))
        is_gateway = ip == self.gateway_ip

        if self.mode == "adaptive" and not old_alive and flips < 2:
            self.rebindings.append({
                "timestamp": now, "ip": ip, "old_mac": old_mac, "new_mac": mac,
                "old_mac_idle_s": round(old_idle, 1) if old_idle is not None else None,
            })
            return None

        if now - self._last_alert.get(ip, float("-inf")) < self._cfg.arp_cooldown_s:
            return None
        self._last_alert[ip] = now

        severity = "HIGH" if (is_gateway or flips >= 2 or len(claimed_ips) > 1) else "MEDIUM"
        idle_txt = (
            f"{old_idle:.1f}s ago" if old_idle is not None else "never (seen only via ARP)"
        )
        factors = [
            f"Previous MAC {old_mac} last sent a frame {idle_txt}.",
            f"{flips} mapping change(s) for {ip} in the last {_FLIP_WINDOW_S / 60:.0f} min.",
        ]
        if is_gateway:
            factors.append(f"{ip} is the default gateway — a classic MITM target.")
        if len(claimed_ips) > 1:
            factors.append(f"{mac} also claims: {', '.join(i for i in claimed_ips if i != ip)}.")

        if self.mode == "adaptive":
            reason = (
                "the previous MAC is still active (two devices claim one IP)"
                if old_alive else f"the mapping has flip-flopped {flips} times"
            )
            rule = "old MAC active within conflict window OR ≥ 2 changes in 10 min"
            summary = f"{ip} moved from {old_mac} to {mac} and {reason}."
            metric = "seconds since the previous MAC was last seen"
            observed = round(old_idle, 1) if old_idle is not None else -1
            threshold = self._cfg.arp_conflict_window_s
        else:
            rule = "any IP→MAC change (fixed)"
            summary = f"The MAC address for {ip} changed from {old_mac} to {mac}."
            metric = "IP→MAC mapping changes"
            observed = flips
            threshold = 1

        return Alert(
            timestamp=now,
            alert_type="ARP_ANOMALY",
            severity=severity,
            mode=self.mode,
            source_ip=mac,
            target_ip=ip,
            description=(
                f"ARP mapping changed for {ip}: {old_mac} → {mac}. "
                f"Possible ARP spoofing or legitimate hardware change."
            ),
            evidence={
                "ip": ip,
                "old_mac": old_mac,
                "new_mac": mac,
                "arp_op": pkt.arp_op,
                "old_mac_idle_s": round(old_idle, 1) if old_idle is not None else None,
                "changes_10min": flips,
                "is_gateway": is_gateway,
                "ips_claimed_by_new_mac": claimed_ips,
            },
            explanation=explain(
                summary=summary, metric=metric, observed=observed,
                threshold=threshold, rule=rule, factors=factors,
            ),
        )

    def tick(self, now: float) -> None:
        cutoff = now - self._cfg.arp_cooldown_s
        for ip in [i for i, t in self._last_alert.items() if t < cutoff]:
            del self._last_alert[ip]

    def get_arp_table(self) -> dict[str, str]:
        """Return a snapshot of the current ARP table."""
        return dict(self._arp_table)
