// Number and time formatting shared by every view.

export function fmtBytes(n: number | null | undefined, digits = 1): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (Math.abs(v) >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : digits)} ${units[i]}`;
}

/** bytes/second → "12.4 Mbit/s" */
export function fmtRate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec == null) return "—";
  return splitRate(bytesPerSec).join(" ");
}

export function splitRate(bytesPerSec: number): [string, string] {
  const bits = bytesPerSec * 8;
  if (bits >= 1e9) return [(bits / 1e9).toFixed(2), "Gbit/s"];
  if (bits >= 1e6) return [(bits / 1e6).toFixed(2), "Mbit/s"];
  if (bits >= 1e3) return [(bits / 1e3).toFixed(1), "kbit/s"];
  return [bits.toFixed(0), "bit/s"];
}

export function mbps(bytesPerSec: number): number {
  return (bytesPerSec * 8) / 1e6;
}

export function compact(n: number | null | undefined): string {
  if (n == null) return "—";
  if (Math.abs(n) >= 1e9) return (n / 1e9).toFixed(1) + "B";
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + "K";
  return n.toLocaleString();
}

export function fmtNum(n: number | null | undefined, digits = 0): string {
  if (n == null) return "—";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function fmtMs(n: number | null | undefined): string {
  return n == null ? "—" : `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`;
}

export function fmtTime(ts: number, withSeconds = true): string {
  return new Date(ts * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit", minute: "2-digit", ...(withSeconds ? { second: "2-digit" } : {}),
  });
}

export function fmtClock(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export function fmtDateTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function fmtAgo(ts: number, now = Date.now() / 1000): string {
  const s = Math.max(0, now - ts);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function fmtDuration(s: number): string {
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

export const ALERT_LABEL: Record<string, string> = {
  PORT_SCAN: "Port scan",
  SYN_FLOOD: "SYN flood",
  ARP_ANOMALY: "ARP anomaly",
  TRAFFIC_SPIKE: "Traffic spike",
};

export const COMPONENT_LABEL: Record<string, string> = {
  latency: "Latency",
  packet_loss: "Packet loss",
  bandwidth: "Bandwidth",
  threats: "Threats",
};

export function endpoint(ip: string | null, port: number | null): string {
  if (!ip) return "—";
  return port == null ? ip : `${ip}:${port}`;
}
