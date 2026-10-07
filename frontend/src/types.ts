// Shapes returned by the NetVision API (see backend/api/routes).

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertType = "PORT_SCAN" | "SYN_FLOOD" | "ARP_ANOMALY" | "TRAFFIC_SPIKE";
export type AlertStatus = "ACTIVE" | "ACKNOWLEDGED" | "RESOLVED";
export type Mode = "static" | "adaptive";

export interface Packet {
  id: string;
  seq: number;
  timestamp: number;
  src_mac: string | null;
  dst_mac: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  ttl: number | null;
  protocol: string;
  transport: string | null;
  src_port: number | null;
  dst_port: number | null;
  tcp_flags: string | null;
  tcp_seq: number | null;
  tcp_ack: number | null;
  tcp_window: number | null;
  payload_len: number;
  icmp_type: number | null;
  icmp_code: number | null;
  icmp_id: number | null;
  icmp_seq: number | null;
  arp_op: string | null;
  arp_sender_mac: string | null;
  arp_sender_ip: string | null;
  arp_target_mac: string | null;
  arp_target_ip: string | null;
  dns_query_name: string | null;
  dns_query_type: string | null;
  dns_response_ips: string[];
  dns_is_response: boolean;
  size: number;
  raw_summary: string;
}

export interface Ranked {
  ip: string;
  name: string;
  bytes: number;
  bps: number;
  pct: number;
  scope: "local" | "external";
}

export interface HealthComponent {
  name: "latency" | "packet_loss" | "bandwidth" | "threats";
  score: number | null;
  weight: number;
  effective_weight: number;
  points_lost: number;
  value: number | null;
  unit: string;
  status: "good" | "degraded" | "bad" | "unknown";
  reason: string;
  culprit?: { ip: string; name: string; pct: number };
}

export interface Snapshot {
  timestamp: number;
  download_bps: number;
  upload_bps: number;
  lan_bps: number;
  total_bps: number;
  instant_bps: number;
  download_mbps: number;
  upload_mbps: number;
  total_mbps: number;
  packets_per_sec: number;
  protocol_dist: Record<string, { count: number; pct: number }>;
  top_talkers: Ranked[];
  top_destinations: Ranked[];
  latency_ms: number | null;
  latency_p95_ms: number | null;
  jitter_ms: number | null;
  rtt_samples: number;
  packet_loss_pct: number | null;
  retransmissions: number;
  active_connections: number;
  half_open_connections: number;
  tcp_states: Record<string, number>;
  host_count: number;
  health_score: number;
  health: { score: number; components: HealthComponent[]; issues: string[] };
  total_packets: number;
  total_bytes: number;
}

export interface Explanation {
  summary: string;
  metric: string;
  observed: number;
  threshold: number;
  rule: string;
  baseline: { mean: number; std: number; samples: number; ready: boolean; scope: string } | null;
  z_score: number | null;
  factors: string[];
}

export interface Alert {
  alert_id: string;
  seq: number;
  timestamp: number;
  alert_type: AlertType;
  severity: Severity;
  status: AlertStatus;
  mode: Mode;
  source_ip: string | null;
  target_ip: string | null;
  description: string;
  evidence: Record<string, unknown>;
  explanation: Explanation | Record<string, never>;
}

export interface CaptureStatus {
  running: boolean;
  source: "live" | "replay" | null;
  interface: string | null;
  replay_file: string | null;
  description: string;
  uptime_seconds: number;
  total_packets: number;
  total_bytes: number;
  error: string | null;
}

export interface PipelineMetrics {
  timestamp?: number;
  received_pps?: number;
  processed_pps?: number;
  dropped_pps?: number;
  avg_processing_us?: number | null;
  capacity_pps?: number | null;
  queue_depth?: number;
}

export interface LiveUpdate {
  type: "live_update";
  timestamp: number;
  packets: Packet[];
  stats: Snapshot | null;
  new_alerts: Alert[];
  capture: CaptureStatus;
  pipeline: PipelineMetrics;
  detection_mode: Mode;
}

export interface Flow {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  transport: string;
  start_time: number;
  last_seen: number;
  duration: number;
  total_packets: number;
  total_bytes: number;
  fwd_bytes: number;
  bwd_bytes: number;
  tcp_state: string;
  handshake_rtt_ms: number | null;
  retransmissions: number;
}

export interface TopoNode {
  id: string;
  ip: string;
  name: string;
  hostnames: string[];
  mac: string | null;
  role: "self" | "gateway" | "lan" | "external";
  bytes: number;
  bytes_sent: number;
  bytes_recv: number;
  last_seen: number | null;
}

export interface TopoEdge {
  source: string;
  target: string;
  bytes: number;
  bytes_ab: number;
  bytes_ba: number;
  packets: number;
  flows: number;
  active_flows: number;
  protocols: string[];
  ports: number[];
}

export interface Topology {
  gateway: string | null;
  nodes: TopoNode[];
  edges: TopoEdge[];
  truncated: boolean;
  total_hosts: number;
}

export interface NetInterface {
  name: string;
  friendly_name: string;
  addresses: string[];
  mac: string | null;
  is_up: boolean;
  is_loopback: boolean;
}
