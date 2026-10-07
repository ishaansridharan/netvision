# NetVision

Real-time, flow-aware network traffic monitoring with explainable, rule-based anomaly detection using adaptive thresholds.

NetVision captures packets, parses Ethernet/ARP/IPv4/TCP/UDP/ICMP/DNS, groups them into bidirectional flows with TCP state, computes network-health statistics over rolling windows, and detects port scans, SYN floods, ARP mapping anomalies and traffic spikes. Each detector runs in either **static** mode (fixed thresholds) or **adaptive** mode (EWMA + z-score baselines with flow context). Every alert says why it fired. A five-view dashboard (Dashboard, Live Packets, Network Map, Security, Reports) shows it all live.

---

## Quick start

Requirements: Python 3.11+, Node 20+.

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt        # Windows: .venv\Scripts\pip
cd frontend && npm install && npm run build && cd ..
.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://localhost:8000** (UI) or **http://localhost:8000/docs** (API).

### Try it without capture privileges

```bash
.venv/bin/python -m evaluation.sample_capture        # writes captures/sample.pcap (+ labels)
```

Then in the UI: **Start capture → Replay capture → sample.pcap**. The capture is benign traffic (browsing, DNS, pings, one large download) and is replayed at its original pace, so every view behaves as with live traffic.

### Live capture

| OS | Requirement |
|---|---|
| Linux | root, or once: `sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"` |
| Windows | [Npcap](https://npcap.com/) with *WinPcap API-compatible mode*, terminal run as Administrator |

Then **Start capture → Live interface**. An optional BPF filter (e.g. `tcp or arp`) is supported.

### Frontend development

```bash
cd frontend && npm run dev          # http://localhost:5173/ui/ — proxies the API to :8000
```

---

## Architecture

```
            ┌──────────────── capture/engine.py ─────────────────┐
 NIC / pcap │ source thread ── raw frames ──▶ bounded queue ──▶  │ analysis worker (1 thread)
            │ (Scapy socket, no dissection)   (drops counted)    │
            └────────────────────────────────────────────────────┘
                                                                   │ parser/fast_parser.py  (~13 µs/packet)
                                                                   ▼
                                                             PacketRecord
                         ┌──────────────────────── pipeline.py ────────────────────────┐
                         │ HostRegistry ─▶ FlowTracker ─▶ StatsEngine ─▶ AnomalyDetector│
                         │ (local/remote,  (5-tuple flows,  (1 s buckets,  (scan, flood, │
                         │  DNS names,      TCP states,      latency,       ARP per pkt; │
                         │  gateway)        half-open,       jitter, loss,  spike + base-│
                         │                  retransmits)     health)        lines per s) │
                         └──────────────────────────────────────────────────────────────┘
                                   │ tick(now) every 1 s, on packet time
                                   ▼
            SQLite (alerts, flows, 1 s snapshots)   ◀──  FastAPI REST + WebSocket /ws/live  ──▶  React UI
```

Design points:

- **Packet time, not wall time.** Every component runs on packet timestamps and an explicit `tick(now)`. The same `Pipeline` serves the live server, pcap replay, the evaluation harness and the tests, so evaluation results are deterministic.
- **Capture and analysis are decoupled.** The source thread only enqueues raw bytes. If analysis falls behind, the queue fills and drops are *counted* instead of being lost silently in the kernel.
- **Raw-byte parsing.** Scapy opens the sockets and reads files, but frames are decoded by a `struct`-based parser. That cuts per-packet cost from about 210 µs (full Scapy dissection) to about 13 µs. The test suite checks it field by field against the Scapy reference parser.

---

## Detection

All four detectors run in either mode. Switch at runtime from the Security view or with `PUT /detection/mode`. Baselines keep learning in both modes.

| Detector | Signal (flow context) | Static rule | Adaptive rule |
|---|---|---|---|
| **Port scan** | Distinct destination ports per source in 5 s, counted from *connection attempts* (new SYN/UDP flows), so server replies never count | ≥ 15 ports | ≥ max(8, μ + 3σ); judged against the source's own baseline once learned, else the network's |
| **SYN flood** | SYNs per destination plus **half-open ratio** from the TCP state machine (attempts older than 0.5 s that never completed) | ≥ 200 SYNs / 10 s **and** ≥ 80 % half-open | SYN rate ≥ max(20/s, μ + 3σ) **and** ≥ 50 % half-open |
| **ARP anomaly** | IP→MAC changes, plus whether the *previous* MAC is still sending frames | any mapping change | change while the old MAC was active in the last 120 s (two devices claim one IP), or ≥ 2 changes in 10 min. A silent old MAC counts as a legitimate re-binding |
| **Traffic spike** | Total throughput of the last full second | ≥ 10 Mbit/s for 2 s | ≥ max(μ + 3σ, 3μ, 1 Mbit/s) for 2 s |

**Baselines** (`detection/baseline.py`) are EWMA mean and variance (α = 0.05) with a 30-sample warm-up. Two safeguards stop attacks from becoming "normal":

- Samples are clipped at μ + 1σ before learning. Clipping at the alert threshold instead would inflate σ by about 38 % per second during a sustained attack (the derivation is in the module docstring).
- During warm-up, samples are clipped at the static threshold.

Baselines learn only while a capture is running, so idle time can't teach the system that the network is silent.

**Explainability.** Every alert carries `explanation`: a plain-language summary, the metric, the observed value, the threshold, the rule, the baseline μ/σ and its scope, the z-score, and supporting evidence (for example "94 % of TCP attempts were refused or unanswered"). The Security view renders it.

---

## Evaluation (static vs adaptive)

The harness implements the report's evaluation plan. It replays a labelled capture through a static pipeline and an adaptive pipeline, which see identical input, and scores both.

1. **Record** a capture in an **isolated lab network you control** (VMs or network namespaces) while running normal traffic plus the report's scenarios. Run any test tools only against machines you own or are authorised to test. Save the file into `captures/`.
2. **Label** the scenarios as you run them:
   ```bash
   python -m evaluation.mark --labels captures/lab1.labels.json start PORT_SCAN --source 10.10.0.66 --target 10.10.0.20
   python -m evaluation.mark --labels captures/lab1.labels.json end PORT_SCAN
   ```
   Also run legitimate look-alikes (a big download, a busy server, a DHCP re-assignment) and leave them **unlabelled**. They are the false positives the comparison is meant to count. The file format is documented in `evaluation/labels.py`.
3. **Score:**
   ```bash
   python -m evaluation.run_eval captures/lab1.pcap [captures/lab2.pcap ...] --name lab-oct
   ```
   This writes precision, recall, F1, false-positive rate, false alerts per hour, detection latency and offline throughput to `evaluation/results/<name>/` as `report.md`, `metrics.csv`, per-alert CSVs and charts. The Reports view shows the latest run.
4. **Throughput and packet drop rate** on the live capture path:
   ```bash
   python -m evaluation.benchmark captures/lab1.pcap --rates 5000 10000 20000 40000
   ```

Metric definitions are in `evaluation/metrics.py`. Briefly:
- An alert inside a same-type incident window (+5 s grace) is a true positive.
- An alert inside a different incident type is *secondary* and is reported but excluded from precision.
- Every other alert is a false positive.
- FPR is the share of normal 10-second bins that contain an alert.

Reference numbers on one laptop core, using the sample capture:

| Measure | Value |
|---|---|
| Fast parser | ~80k packets/s |
| Analysis pipeline | ~95k packets/s |
| Live path, no drops | up to ~30k packets/s offered |
| Live path, saturated | ~30k packets/s |

The sample capture has a single labelled event. It shows the harness works, not that one mode beats the other. **Use your lab captures for the report's comparison.**

---

## API

| Area | Endpoints |
|---|---|
| Capture | `GET /interfaces` · `POST /capture/start {interface?, bpf_filter?}` · `GET /capture/files` · `POST /capture/replay {file, speed, loop}` · `POST /capture/stop` · `GET /capture/status` |
| Packets & flows | `GET /packets` (filters: protocol, ip, port, search, since_seq…) · `GET /packets/{id}` · `GET /flows` · `GET /flows/stats` · `GET /flows/{id}` |
| Statistics | `GET /stats/current` · `GET /stats/history` · `GET /stats/health` · `GET /stats/arp` |
| Hosts & map | `GET /topology` · `GET /hosts` · `GET /hosts/{ip}` |
| Security | `GET /alerts` · `GET /alerts/summary` · `GET /alerts/{id}` · `PATCH /alerts/{id}/status` · `GET /detection/config` · `PUT /detection/mode` · `GET /detection/baselines` |
| Reports | `GET /reports/summary?minutes=` · `GET /reports/diagnosis` · `GET /reports/evaluation` · `GET /metrics/pipeline` |
| Live | `WS /ws/live` pushes every 500 ms: new packets, latest stats, new alerts, capture and pipeline status. Send `{"packet_limit": N}` or `{"packets": false}` |

Full schemas: http://localhost:8000/docs

---

## Configuration

Every setting in `backend/config.py` can be overridden with an environment variable or a `.env` file. See `.env.example`.

## Tests

```bash
.venv/bin/python -m pytest              # ~75 tests, ~20 s
.venv/bin/python -m pytest -m "not slow" # skip the end-to-end harness test
cd frontend && npm run typecheck
```

## Project structure

```
backend/
  main.py              FastAPI app, lifecycle, static UI + evaluation charts
  config.py            all thresholds and limits
  pipeline.py          Pipeline: hosts → flows → stats → detection, tick on packet time
  capture/             engine (queue + worker, live + replay), interfaces, pcap reader
  parser/              fast_parser (raw bytes, production) · packet_parser (Scapy reference)
  analyzer/            hosts, flow_tracker, stats_engine
  detection/           baseline (EWMA), port_scan, syn_flood, arp_anomaly, traffic_spike, detector
  storage/             SQLite models, background writer, report queries
  api/                 shared state, routes/, websocket
frontend/src/          React + Vite: views/ (five views), components/, live.tsx (WebSocket store)
evaluation/            metrics, run_eval, benchmark, charts, labels, mark, sample_capture
tests/                 parser, flows, stats, baselines, detectors, engine, API, evaluation
```

## Status and remaining work

The pipeline, all four detectors in both modes, the API, the database, the five-view dashboard and the evaluation harness are implemented and tested. Two goals from the project report are still open.

### Implemented

Mapped to the report's pipeline: Capture → Parse → Flow Tracking → Statistics → Detection → Visualization.

| Stage | What is implemented | Where |
|---|---|---|
| **Capture** | Live capture from an interface (optional BPF filter), and replay of `.pcap`/`.pcapng` files at original pace or faster. The capture thread only enqueues raw frames; one analysis worker does the rest, and packets the queue can't accept are counted as drops. Clear error messages when capture privileges are missing. | `capture/engine.py`, `capture/pcapfile.py`, `capture/interface.py` |
| **Parse** | Ethernet (incl. VLAN tags), ARP, IPv4 (options, fragments), ICMP (echo id/seq), TCP (flags, seq/ack, payload length), UDP and DNS (queries, answers, name compression). A byte-level parser handles about 80k packets/s and is checked field by field against a Scapy reference parser. | `parser/fast_parser.py`, `parser/packet_parser.py` |
| **Flow tracking** | Bidirectional 5-tuple flows that remember the initiator. A TCP state machine covers SYN_SENT → SYN_RECEIVED → ESTABLISHED → FIN_WAIT → CLOSED/RESET, with a half-open flag, handshake RTT and retransmission counting. Expiry depends on state, and a hard cap protects against floods. | `analyzer/flow_tracker.py` |
| **Statistics** | Upload/download/LAN bandwidth over 10 s windows plus a 1 s rate. Packets/s, protocol mix, and top talkers and destinations with DNS-resolved names. Latency (median and p95 from ping and handshake RTTs), jitter, a loss estimate, active and half-open connections, and a 0–100 health score that explains each component and names the host responsible. | `analyzer/stats_engine.py`, `analyzer/hosts.py` |
| **Detection** | Port scan, SYN flood, ARP anomaly and traffic spike, each in static and adaptive mode, switchable at runtime. Adaptive baselines are EWMA mean/variance with z-scores, per-host where history exists, and protected against learning from attacks or idle time. Every alert carries an explanation: rule, observed value, threshold, baseline and supporting evidence. Details in [Detection](#detection). | `detection/` |
| **Storage** | SQLite holds alerts (with explanations and status changes), completed flows and 1-second stats snapshots. Writes go through a background writer, alerts are restored on restart, and old data is pruned on a schedule. | `storage/` |
| **API** | REST endpoints for capture, packets, flows, stats, hosts, topology, alerts, detection mode and baselines, reports and pipeline metrics, plus a WebSocket that pushes updates every 500 ms. Details in [API](#api). | `api/`, `main.py` |
| **Visualization** | The five views from the report, with light and dark themes. **Dashboard:** health breakdown, KPIs, traffic chart, protocols, top sources, recent alerts. **Live Packets:** filters, pause, per-layer detail. **Network Map:** force-directed host graph plus a connections table. **Security:** mode switch, alert list with explanation panel, acknowledge/resolve, live baselines, ARP table. **Reports:** "why is my network slow?" diagnosis, history trends, top devices and services, alert history, processing performance, evaluation results. | `frontend/src/` |
| **Evaluation** | Labelling tool, a scorer that replays a capture through static and adaptive pipelines side by side (precision, recall, F1, false-positive rate, false alerts per hour, detection latency, offline throughput, with tables and charts), a live-path throughput and drop-rate benchmark, and a benign sample capture for demos. Details in [Evaluation](#evaluation-static-vs-adaptive). | `evaluation/` |
| **Tests** | 74 tests covering the parsers, flows, stats, baselines, all detectors in both modes, the capture engine, the API (including replay end to end) and the evaluation harness. | `tests/` |

### Open goals

1. **Static-vs-adaptive results.** The report promises comparison tables and graphs (precision, recall, F1, false-positive rate, detection latency) on mixed normal and attack traffic. The harness that produces them works, but it hasn't been run on real data. The only capture so far is the generated benign sample, which shows the harness works and nothing about which mode is better. The claim that adaptive detection reduces false positives is **not yet demonstrated**. To close it:
   - Set up an isolated lab (two or three VMs, or Linux network namespaces) that you control.
   - Record normal traffic plus the report's scenarios (port scan, SYN flood, ARP spoofing), labelling each with `evaluation.mark`.
   - Also record legitimate look-alikes (a large download, a busy server, a DHCP re-assignment) and leave them **unlabelled**. They are where static thresholds should produce false positives and adaptive detection should not.
   - Record several runs so the results don't rest on a single capture, then follow [Evaluation](#evaluation-static-vs-adaptive).
2. **Live capture on a real interface.** The live capture loop has only been tested with a simulated socket. It still needs one manual session on a real Linux interface, and one on Windows with Npcap (the report's stated platform, not yet run at all).

### Not yet done

- **Threshold sweep.** k = 3, α = 0.05 and the floors are reasonable defaults, not values tuned on data. Once lab captures exist, sweeping k and plotting detection rate against false-positive rate (an ROC-style curve) would strengthen the evaluation. `run_eval` doesn't support sweeps yet.
- **Direction on the Network Map.** Per-direction byte counts are in the Connections table, but the graph doesn't draw direction arrows.
- **Frontend tests.** The UI has no automated tests. It was checked by screenshots in light mode at desktop width only; dark mode and narrow screens haven't been verified.

### Suggested order

1. Run a live capture on Linux, then on Windows.
2. Record two or three labelled lab captures.
3. Run the evaluation and add the threshold sweep.
4. Put the resulting tables and charts into the report.

## Known limitations

- **IPv4 only.** IPv6 frames are skipped.
- **Port-scan coverage.** The metric is distinct-port fan-out, so a horizontal sweep of one port across many hosts isn't flagged by it. The alert evidence does report target counts.
- **Latency** needs ICMP echo pairs or new TCP handshakes in the last 30 s. **Packet loss** is estimated from TCP retransmissions only.
- **Adaptive warm-up.** Detectors use the static rule for the first ~30 s of observation. A host's own baseline adapts to lasting behaviour changes over minutes, deliberately, so an attacker can't retrain it quickly.
- **ARP adaptive mode** needs to have seen the old MAC to judge whether it's still alive. The OS ARP cache is used as a seed at capture start.
- **Throughput.** Analysis is single-threaded Python, at roughly 30k packets/s sustained on one core.
- **No authentication.** The API has no login and CORS allows any origin, so anyone who can reach the port can view traffic and start or stop capture. Keep the server bound to `127.0.0.1` (as in [Quick start](#quick-start)) unless the network is trusted.
