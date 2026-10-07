import { useMemo, useState } from "react";
import { Card, Empty, Icon } from "../components/ui";
import { endpoint, fmtClock, fmtDateTime } from "../format";
import { useLive } from "../live";
import type { Packet } from "../types";

const PROTOCOLS = ["", "TCP", "UDP", "DNS", "ICMP", "ARP"];
const MAX_ROWS = 300;

function matches(p: Packet, f: { proto: string; ip: string; port: string; search: string }): boolean {
  if (f.proto && p.protocol !== f.proto && p.transport !== f.proto) return false;
  if (f.ip && !(p.src_ip?.includes(f.ip) || p.dst_ip?.includes(f.ip))) return false;
  if (f.port) {
    const n = Number(f.port);
    if (p.src_port !== n && p.dst_port !== n) return false;
  }
  if (f.search && !p.raw_summary.toLowerCase().includes(f.search.toLowerCase())) return false;
  return true;
}

export function Packets() {
  const { packets } = useLive();
  const [frozen, setFrozen] = useState<Packet[] | null>(null);
  const [proto, setProto] = useState("");
  const [ip, setIp] = useState("");
  const [port, setPort] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Packet | null>(null);

  const source = frozen ?? packets;
  const rows = useMemo(
    () => source.filter((p) => matches(p, { proto, ip: ip.trim(), port: port.trim(), search: search.trim() })).slice(0, MAX_ROWS),
    [source, proto, ip, port, search],
  );

  return (
    <>
      <Card>
        <div className="filters">
          <select className="select" value={proto} onChange={(e) => setProto(e.target.value)} aria-label="Protocol">
            {PROTOCOLS.map((p) => <option key={p} value={p}>{p || "All protocols"}</option>)}
          </select>
          <input className="input" placeholder="IP address" value={ip} onChange={(e) => setIp(e.target.value)} style={{ width: 150 }} />
          <input className="input" placeholder="Port" value={port} inputMode="numeric"
            onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} style={{ width: 90 }} />
          <input className="input" placeholder="Search summary…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ flex: 1, minWidth: 160 }} />
          <button className="btn" onClick={() => setFrozen(frozen ? null : [...packets])}>
            {frozen ? <><Icon.play /> Resume</> : <><Icon.pause /> Pause</>}
          </button>
          <span className="muted num" style={{ fontSize: 12 }}>
            {rows.length} shown{frozen ? " · paused" : ""} · newest first
          </span>
        </div>
      </Card>

      <Card>
        {rows.length === 0 ? <Empty>No packets match.</Empty> : (
          <div className="table-wrap scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th>
                  <th className="num">Size</th><th>Flags</th><th>Info</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr key={p.id} className={`clickable${selected?.id === p.id ? " selected" : ""}`} onClick={() => setSelected(p)}>
                    <td className="mono" style={{ fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>{fmtClock(p.timestamp)}</td>
                    <td className="mono">{endpoint(p.src_ip, p.src_port)}</td>
                    <td className="mono">{endpoint(p.dst_ip, p.dst_port)}</td>
                    <td><span className="pill">{p.protocol}</span></td>
                    <td className="num">{p.size}</td>
                    <td className="mono">{p.tcp_flags ?? ""}</td>
                    <td className="ink-2" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {p.raw_summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && <PacketDrawer p={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function Section({ title, rows }: { title: string; rows: [string, unknown][] }) {
  const shown = rows.filter(([, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length));
  if (!shown.length) return null;
  return (
    <div>
      <div className="section-title">{title}</div>
      <dl className="kv">
        {shown.map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <dt>{k}</dt><dd className="mono">{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function PacketDrawer({ p, onClose }: { p: Packet; onClose: () => void }) {
  return (
    <aside className="drawer" role="dialog" aria-label="Packet details">
      <header>
        <h3>Packet #{p.seq}</h3>
        <button className="btn" onClick={onClose} aria-label="Close"><Icon.x /></button>
      </header>
      <div className="body">
        <div className="ink-2">{p.raw_summary}</div>
        <Section title="Frame" rows={[["Captured", fmtDateTime(p.timestamp)], ["Size", `${p.size} bytes`], ["Protocol", p.protocol]]} />
        <Section title="Ethernet" rows={[["Source MAC", p.src_mac], ["Destination MAC", p.dst_mac]]} />
        {p.protocol === "ARP" ? (
          <Section title="ARP" rows={[
            ["Operation", p.arp_op], ["Sender", `${p.arp_sender_ip} (${p.arp_sender_mac})`],
            ["Target", `${p.arp_target_ip} (${p.arp_target_mac})`],
          ]} />
        ) : (
          <Section title="IPv4" rows={[["Source", p.src_ip], ["Destination", p.dst_ip], ["TTL", p.ttl]]} />
        )}
        {p.transport === "TCP" && (
          <Section title="TCP" rows={[
            ["Ports", `${p.src_port} → ${p.dst_port}`], ["Flags", p.tcp_flags], ["Sequence", p.tcp_seq],
            ["Acknowledgement", p.tcp_ack], ["Window", p.tcp_window], ["Payload", `${p.payload_len} bytes`],
          ]} />
        )}
        {p.transport === "UDP" && (
          <Section title="UDP" rows={[["Ports", `${p.src_port} → ${p.dst_port}`], ["Payload", `${p.payload_len} bytes`]]} />
        )}
        {p.transport === "ICMP" && (
          <Section title="ICMP" rows={[["Type", p.icmp_type], ["Code", p.icmp_code], ["Identifier", p.icmp_id], ["Sequence", p.icmp_seq]]} />
        )}
        {p.dns_query_name && (
          <Section title="DNS" rows={[
            ["Kind", p.dns_is_response ? "Response" : "Query"], ["Name", p.dns_query_name],
            ["Type", p.dns_query_type], ["Answers", p.dns_response_ips],
          ]} />
        )}
      </div>
    </aside>
  );
}
