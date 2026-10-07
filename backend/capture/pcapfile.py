"""
NetVision — Raw capture-file reader (capture/pcapfile.py)

Yields (frame_bytes, timestamp, linktype) from .pcap and .pcapng files
without dissecting packets, for the fast parser.
"""

from __future__ import annotations

from typing import Iterator


def iter_raw(path: str) -> Iterator[tuple[bytes, float, int]]:
    # scapy.all registers the reader classes and link-type tables.
    from scapy.all import RawPcapReader  # type: ignore[import]

    with RawPcapReader(path) as reader:
        nano = getattr(reader, "nano", False)
        file_linktype = getattr(reader, "linktype", 1)
        for data, meta in reader:
            if hasattr(meta, "tshigh"):           # pcapng
                ts = ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol or 1_000_000)
                linktype = meta.linktype
            else:                                 # classic pcap
                ts = meta.sec + meta.usec / (1e9 if nano else 1e6)
                linktype = file_linktype
            yield data, ts, linktype
