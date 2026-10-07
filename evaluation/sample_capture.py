"""
Benign sample capture for demos and harness tests (evaluation/sample_capture.py)

    python -m evaluation.sample_capture [--duration 300] [--out captures/sample.pcap]

Writes a pcap of ordinary traffic from one workstation, built in memory
with Scapy (nothing is sent on any network):

  • DNS lookups followed by HTTPS sessions — full TCP handshakes, request,
    multi-segment response, FIN close — to a rotating set of sites with
    realistic per-site RTTs, plus the occasional retransmission
  • a ping to 1.1.1.1 every 5 seconds
  • ARP request/reply for the gateway every 60 seconds
  • one bulk download burst (labelled TRAFFIC_SPIKE in the labels file)

It is meant to exercise the dashboard through /capture/replay without
capture privileges, and to test the evaluation harness end to end.  It is
not a substitute for the lab captures the report's evaluation calls for.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys

ME, ME_MAC = "10.0.0.5", "02:00:00:00:00:05"
GW, GW_MAC = "10.0.0.1", "02:00:00:00:00:01"
SITES = [
    ("www.google.com", "142.250.183.4", 0.018),
    ("github.com", "140.82.112.3", 0.065),
    ("docs.python.org", "151.101.0.223", 0.030),
    ("stackoverflow.com", "104.18.32.7", 0.024),
    ("en.wikipedia.org", "208.80.154.224", 0.110),
    ("cdn.jsdelivr.net", "151.101.1.229", 0.022),
]
MSS = 1400
T0 = 1_760_000_000.0


class _Builder:
    def __init__(self, seed: int) -> None:
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether
        self.L = dict(DNS=DNS, DNSQR=DNSQR, DNSRR=DNSRR, ICMP=ICMP, IP=IP,
                      TCP=TCP, UDP=UDP, ARP=ARP, Ether=Ether)
        self.rng = random.Random(seed)
        self.out: list = []

    def _add(self, t: float, pkt) -> None:
        pkt.time = T0 + t
        self.out.append(pkt)

    def _out(self, dst: str, l4):
        L = self.L
        return L["Ether"](src=ME_MAC, dst=GW_MAC) / L["IP"](src=ME, dst=dst) / l4

    def _in(self, src: str, l4):
        L = self.L
        return L["Ether"](src=GW_MAC, dst=ME_MAC) / L["IP"](src=src, dst=ME) / l4

    def dns(self, t: float, name: str, ip: str) -> float:
        L = self.L
        qid = self.rng.randint(0, 65535)
        sport = self.rng.randint(32768, 60999)
        self._add(t, self._out(GW, L["UDP"](sport=sport, dport=53) /
                              L["DNS"](id=qid, rd=1, qd=L["DNSQR"](qname=name))))
        t += self.rng.uniform(0.004, 0.012)
        self._add(t, self._in(GW, L["UDP"](sport=53, dport=sport) /
                             L["DNS"](id=qid, qr=1, ra=1, qd=L["DNSQR"](qname=name),
                                      an=L["DNSRR"](rrname=name, type="A", rdata=ip, ttl=300))))
        return t

    def session(self, t: float, ip: str, rtt: float, segments: int,
                spacing: float = 0.0004, retrans_p: float = 0.01) -> float:
        L, rng = self.L, self.rng
        TCP = L["TCP"]
        sp = rng.randint(32768, 60999)
        c, s = rng.randint(0, 2**31), rng.randint(0, 2**31)
        j = lambda: rtt * rng.uniform(0.9, 1.15)

        self._add(t, self._out(ip, TCP(sport=sp, dport=443, flags="S", seq=c)))
        t += j()
        self._add(t, self._in(ip, TCP(sport=443, dport=sp, flags="SA", seq=s, ack=c + 1)))
        t += 0.0005
        c += 1
        s += 1
        self._add(t, self._out(ip, TCP(sport=sp, dport=443, flags="A", seq=c, ack=s)))
        req = 517
        self._add(t + 0.0002, self._out(ip, TCP(sport=sp, dport=443, flags="PA", seq=c, ack=s) / (b"q" * req)))
        c += req
        t += j()
        payload = b"r" * MSS
        for i in range(segments):
            self._add(t, self._in(ip, TCP(sport=443, dport=sp, flags="A", seq=s, ack=c) / payload))
            if rng.random() < retrans_p:   # an occasional lost segment, resent
                self._add(t + rtt * 2, self._in(ip, TCP(sport=443, dport=sp, flags="A", seq=s, ack=c) / payload))
            s += MSS
            t += spacing
            if i % 2 == 1:
                self._add(t, self._out(ip, TCP(sport=sp, dport=443, flags="A", seq=c, ack=s)))
        t += 0.002
        self._add(t, self._out(ip, TCP(sport=sp, dport=443, flags="FA", seq=c, ack=s)))
        t += j()
        self._add(t, self._in(ip, TCP(sport=443, dport=sp, flags="FA", seq=s, ack=c + 1)))
        self._add(t + 0.0005, self._out(ip, TCP(sport=sp, dport=443, flags="A", seq=c + 1, ack=s + 1)))
        return t

    def ping(self, t: float, seq: int) -> None:
        L = self.L
        self._add(t, self._out("1.1.1.1", L["ICMP"](type=8, id=4242, seq=seq)))
        self._add(t + self.rng.uniform(0.012, 0.020),
                  self._in("1.1.1.1", L["ICMP"](type=0, id=4242, seq=seq)))

    def arp(self, t: float) -> None:
        L = self.L
        req = L["Ether"](src=ME_MAC, dst="ff:ff:ff:ff:ff:ff") / L["ARP"](
            op=1, psrc=ME, hwsrc=ME_MAC, pdst=GW)
        rep = L["Ether"](src=GW_MAC, dst=ME_MAC) / L["ARP"](
            op=2, psrc=GW, hwsrc=GW_MAC, pdst=ME, hwdst=ME_MAC)
        self._add(t, req)
        self._add(t + 0.002, rep)


def generate(path: str, duration: float = 300.0, seed: int = 7,
             burst: tuple[float, float] | None = None) -> str:
    """Write the capture and its labels file; returns the labels path."""
    from scapy.utils import wrpcap

    burst = burst or (duration * 0.65, duration * 0.65 + 15)
    b = _Builder(seed)
    rng = b.rng

    for i, t in enumerate(range(0, int(duration), 5)):
        b.ping(t + 0.1, i + 1)
    for t in range(0, int(duration), 60):
        b.arp(t + 0.3)

    t = 0.5
    while t < duration - 2:
        name, ip, rtt = rng.choice(SITES)
        start = b.dns(t, name, ip)
        for _ in range(rng.randint(1, 3)):
            b.session(start + rng.uniform(0, 0.05), ip, rtt, segments=rng.randint(5, 40))
        t += rng.uniform(0.6, 2.2)

    # Bulk download: ~2 MB/s for the burst window
    bt = burst[0]
    while bt < burst[1]:
        b.session(bt, "151.101.0.223", 0.030, segments=700, spacing=0.0007, retrans_p=0.002)
        bt += 0.5

    b.out.sort(key=lambda p: p.time)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    wrpcap(path, b.out)

    labels = {
        "description": "Benign sample: browsing, DNS, pings, gateway ARP, one bulk download burst.",
        "time_base": "absolute",
        "network": {"self_ips": [ME], "local_networks": ["10.0.0.0/24"], "gateway": GW},
        "incidents": [{
            "type": "TRAFFIC_SPIKE", "start": T0 + burst[0], "end": T0 + burst[1],
            "source": "151.101.0.223", "target": ME, "note": "bulk download",
        }],
    }
    labels_path = os.path.splitext(path)[0] + ".labels.json"
    with open(labels_path, "w") as fh:
        json.dump(labels, fh, indent=2)
    return labels_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--duration", type=float, default=300.0)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=os.path.join("captures", "sample.pcap"))
    args = ap.parse_args(argv)
    labels = generate(args.out, args.duration, args.seed)
    print(f"Wrote {args.out} and {labels}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
