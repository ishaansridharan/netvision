"""
NetVision — Network Interface Discovery (capture/interface.py)

Provides utilities to enumerate the machine's network interfaces,
validate a chosen interface, and detect whether Npcap is available
on Windows (required for Scapy packet capture).

Key functions
─────────────
list_interfaces()      → list[InterfaceInfo]
validate_interface()   → bool
check_npcap()          → bool  (Windows only)
get_default_interface()→ str | None
"""

from __future__ import annotations

import platform
import socket
import ipaddress
import logging
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class InterfaceInfo:
    """Structured representation of one network interface."""
    name: str
    friendly_name: str          # Human-readable label (same as name on Linux)
    addresses: list[str]        # IPv4 addresses bound to this interface
    mac: str | None             # MAC address, if available
    is_up: bool                 # Whether the interface is currently up
    is_loopback: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "friendly_name": self.friendly_name,
            "addresses": self.addresses,
            "mac": self.mac,
            "is_up": self.is_up,
            "is_loopback": self.is_loopback,
        }


# ──────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────

def list_interfaces() -> list[InterfaceInfo]:
    """
    Return all network interfaces discovered via psutil.

    psutil is used instead of Scapy here so we don't require Npcap
    just to enumerate interfaces in the UI.
    """
    interfaces: list[InterfaceInfo] = []

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for iface_name, addr_list in addrs.items():
        ipv4_addrs: list[str] = []
        mac: str | None = None
        is_loopback = False

        for addr in addr_list:
            # AF_INET  = IPv4
            if addr.family == socket.AF_INET:
                ipv4_addrs.append(addr.address)
                try:
                    if ipaddress.ip_address(addr.address).is_loopback:
                        is_loopback = True
                except ValueError:
                    pass
            # AF_PACKET (Linux) or psutil-specific MAC family
            elif addr.family == psutil.AF_LINK:
                mac = addr.address if addr.address else None

        iface_stats = stats.get(iface_name)
        is_up = bool(iface_stats and iface_stats.isup)

        interfaces.append(
            InterfaceInfo(
                name=iface_name,
                friendly_name=_friendly_name(iface_name),
                addresses=ipv4_addrs,
                mac=mac,
                is_up=is_up,
                is_loopback=is_loopback,
            )
        )

    # Sort: active non-loopback first, then loopback, then down
    interfaces.sort(key=lambda i: (not i.is_up, i.is_loopback, i.name))
    return interfaces


def validate_interface(name: str) -> bool:
    """Return True if *name* refers to a known interface."""
    known = {iface.name for iface in list_interfaces()}
    return name in known


def get_default_interface() -> str | None:
    """
    Heuristically pick the best interface for capture:
    - active (up)
    - not loopback
    - has an IPv4 address
    Returns None if no suitable interface is found.
    """
    for iface in list_interfaces():
        if iface.is_up and not iface.is_loopback and iface.addresses:
            return iface.name
    return None


def check_npcap() -> dict:
    """
    On Windows, verify that Npcap (or WinPcap) is installed by attempting
    to import Scapy's Windows-specific WinPcap/Npcap bindings.

    Returns a dict:
      { "available": bool, "message": str }
    """
    if platform.system() != "Windows":
        return {"available": True, "message": "Non-Windows system; Npcap not required."}

    try:
        # Scapy defers Npcap loading; we check for the DLL directly.
        import ctypes
        ctypes.WinDLL("wpcap.dll")
        return {"available": True, "message": "Npcap/WinPcap DLL found."}
    except OSError:
        return {
            "available": False,
            "message": (
                "Npcap not found. Install it from https://npcap.com/ and "
                "restart the application. Packet capture will not work without it."
            ),
        }


# ──────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────

def _friendly_name(raw: str) -> str:
    """
    On Windows, psutil may return GUIDs like
    '{4D36E972-E325-11CE-BFC1-08002BE10318}'.
    Attempt to resolve to a human-readable name via the registry.
    Falls back to the raw name on any failure.
    """
    if platform.system() != "Windows":
        return raw

    if not (raw.startswith("{") and raw.endswith("}")):
        return raw  # Already human-readable

    try:
        import winreg  # type: ignore[import]
        key_path = (
            r"SYSTEM\CurrentControlSet\Control\Network"
            rf"\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{raw}\Connection"
        )
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            name, _ = winreg.QueryValueEx(key, "Name")
            return str(name)
    except Exception:
        return raw
