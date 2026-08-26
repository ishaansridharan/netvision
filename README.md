# NetVision — Network Traffic Monitoring & Anomaly Detection

> Real-time network packet capture, protocol analysis, flow tracking, performance metrics, and anomaly detection.

---

## Prerequisites

### 1. Npcap (Windows — Required for packet capture)
Download and install from **https://npcap.com/**  
Install with *"WinPcap API-compatible mode"* **checked**.  
Without Npcap, `POST /capture/start` will return a 503 error.

### 2. Python 3.11+
```
python --version
```

### 3. Administrator Privileges
Packet capture requires elevated privileges on Windows.  
**Right-click your terminal → "Run as Administrator"** before starting the server.

---

## Setup

```bash
# From the project root (NetVision/)
cd backend
pip install -r requirements.txt
```

---

## Running the Server

```bash
# From the project root (NetVision/)
# Must be run as Administrator on Windows!
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

| URL | Description |
|-----|-------------|
| http://localhost:8000/docs | **Swagger UI** — interactive API docs |
| http://localhost:8000/redoc | ReDoc API docs |
| http://localhost:8000/health | Health check |
| ws://localhost:8000/ws/live | WebSocket live feed |

---

## Quick Start Walkthrough

### Step 1 — Check Npcap
```
GET /capture/npcap-check
```

### Step 2 — List interfaces
```
GET /interfaces
```
Pick an interface name from the response (e.g. `"Wi-Fi"` or `"Ethernet"`).

### Step 3 — Start capture
```
POST /capture/start
{ "interface": "Wi-Fi" }
```

### Step 4 — View live packets
```
GET /packets?limit=50
```

### Step 5 — View real-time stats (dashboard data)
```
GET /stats/current
```

### Step 6 — Connect WebSocket
```
ws://localhost:8000/ws/live
```
Receives a JSON push every 500ms with:
- `packets` — latest captured packets
- `stats` — current bandwidth, pps, latency, health score, etc.
- `new_alerts` — any new anomaly detections

---

## API Reference

### Capture Control
| Method | Path | Description |
|--------|------|-------------|
| GET | `/interfaces` | List all network interfaces |
| GET | `/capture/npcap-check` | Verify Npcap is installed |
| POST | `/capture/start` | Start capture `{"interface": "Wi-Fi"}` |
| POST | `/capture/stop` | Stop capture |
| GET | `/capture/status` | Running state, uptime, packet count |

### Packets
| Method | Path | Description |
|--------|------|-------------|
| GET | `/packets` | Recent packets. Filters: `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `min_size`, `max_size` |
| GET | `/packets/{id}` | Single packet detail |

### Flows
| Method | Path | Description |
|--------|------|-------------|
| GET | `/flows` | Active + recent flows. Filters: `protocol`, `src_ip`, `dst_ip`, `active_only` |
| GET | `/flows/stats` | Flow count summary |

### Statistics
| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats/current` | Latest snapshot: bandwidth, pps, latency, top talkers, health |
| GET | `/stats/history` | Time-series for charting (default 300 snapshots) |
| GET | `/stats/health` | Health score breakdown |
| GET | `/stats/arp` | Observed IP→MAC ARP table |

### Alerts
| Method | Path | Description |
|--------|------|-------------|
| GET | `/alerts` | All alerts. Filters: `severity`, `alert_type`, `status` |
| GET | `/alerts/summary` | Count by severity/type/status |
| GET | `/alerts/{id}` | Single alert detail |
| PATCH | `/alerts/{id}/status` | `{"status": "ACKNOWLEDGED"}` or `"RESOLVED"` |

### System
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + component status |

### WebSocket
| Path | Description |
|------|-------------|
| `WS /ws/live` | Push every 500ms: packets, stats, new alerts |

Send `{"packet_limit": N}` to configure packets per push (max 200).

---

## Architecture

```
Network Interface
      ↓
CaptureEngine  (capture/engine.py)
      ↓ PacketRecord
  ┌───┴──────────────────────┐
  │ _pipeline_callback        │
  ├──────────────────────────┤
  ↓                          ↓                          ↓
FlowTracker             StatsEngine              AnomalyDetector
(analyzer/              (analyzer/               (detection/
 flow_tracker.py)        stats_engine.py)         detector.py)
      │                      │                         │
      │               ┌──────┘                   ┌────┘
      │               ↓                          ↓
      │        Protocol/Bandwidth          PortScan │ SynFlood
      │        Latency/Jitter/Loss         ArpAnomaly│ TrafficSpike
      │               │                          │
      └───────────────┴──────────────────────────┘
                      ↓
               FastAPI REST API
                      +
               WebSocket /ws/live
                      ↓
               React Frontend (Person 2)
```

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| **Port Scan** | Single source contacts ≥15 distinct ports within 5s | HIGH |
| **SYN Flood** | ≥200 SYNs to one destination with >80% incomplete handshakes within 10s | HIGH |
| **ARP Anomaly** | IP→MAC mapping changes unexpectedly | MEDIUM |
| **Traffic Spike** | Current bandwidth > 3× EMA baseline (min baseline: 10 KB/s) | MEDIUM |

All thresholds are configurable in `backend/config.py` or via `.env` file.

## Configuration

Create a `.env` file in the project root to override defaults:

```env
# Detection thresholds
PORT_SCAN_THRESHOLD=20
PORT_SCAN_WINDOW_S=5.0
SYN_FLOOD_SYN_THRESHOLD=300
TRAFFIC_SPIKE_MULTIPLIER=4.0

# Rolling stats window
STATS_ROLLING_WINDOW_S=10.0

# Debug logging
DEBUG=true
```

## Project Structure

```
NetVision/
└── backend/
    ├── main.py              # FastAPI entry point
    ├── config.py            # Configurable settings
    ├── requirements.txt
    ├── capture/
    │   ├── engine.py        # Scapy capture loop (background thread)
    │   └── interface.py     # Interface discovery + Npcap check
    ├── parser/
    │   └── packet_parser.py # Raw Scapy → PacketRecord
    ├── analyzer/
    │   ├── flow_tracker.py  # 5-tuple bidirectional flow tracking
    │   ├── stats_engine.py  # Bandwidth, latency, jitter, health score
    │   └── protocol_stats.py# Protocol distribution tracker
    ├── detection/
    │   ├── detector.py      # Orchestrator — all rules
    │   ├── models.py        # Alert dataclass
    │   ├── port_scan.py     # Port scan detection
    │   ├── syn_flood.py     # SYN flood pattern detection
    │   ├── arp_anomaly.py   # ARP spoofing detection
    │   └── traffic_spike.py # EMA-based traffic spike detection
    ├── storage/
    │   ├── database.py      # SQLite + async write queue
    │   └── models.py        # SQLAlchemy ORM models
    └── api/
        ├── state.py         # Singleton component instances + pipeline wiring
        ├── websocket.py     # WS /ws/live live feed
        └── routes/
            ├── interfaces.py
            ├── packets.py
            ├── flows.py
            ├── stats.py
            ├── alerts.py
            └── health.py
```
