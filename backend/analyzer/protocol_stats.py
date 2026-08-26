"""
NetVision — Protocol Statistics Tracker (analyzer/protocol_stats.py)

Maintains a running count and percentage breakdown of observed protocols.
Reset-able for rolling-window calculations.
"""

from __future__ import annotations

import threading
from collections import defaultdict


class ProtocolStats:
    """Thread-safe protocol counter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = defaultdict(int)
        self._total: int = 0

    def record(self, protocol: str) -> None:
        with self._lock:
            self._counts[protocol] += 1
            self._total += 1

    def snapshot(self) -> dict:
        """Return {protocol: {count, pct}} sorted by count descending."""
        with self._lock:
            total = self._total
            counts = dict(self._counts)

        result: dict[str, dict] = {}
        for proto, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            result[proto] = {
                "count": cnt,
                "pct": round(cnt / total * 100, 1) if total else 0.0,
            }
        return result

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
            self._total = 0

    @property
    def total(self) -> int:
        return self._total
