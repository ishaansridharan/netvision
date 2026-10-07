import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import {
  forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation,
  type Simulation, type SimulationLinkDatum, type SimulationNodeDatum,
} from "d3-force";
import { api } from "../api";
import { Card, Empty, Icon, Legend, SeverityBadge } from "../components/ui";
import { ALERT_LABEL, endpoint, fmtAgo, fmtBytes } from "../format";
import { usePoll } from "../live";
import type { Alert, Flow, TopoEdge, TopoNode, Topology } from "../types";

// Three categorical slots validate for all-pairs use; "external" is the
// catch-all and takes neutral ink instead of a fourth hue.
const ROLE_COLOR: Record<TopoNode["role"], string> = {
  self: "var(--series-1)", gateway: "var(--series-2)", lan: "var(--series-3)", external: "var(--series-neutral)",
};
const ROLE_LABEL: Record<TopoNode["role"], string> = {
  self: "This machine", gateway: "Gateway", lan: "LAN device", external: "External host",
};
const HEIGHT = 560;
const LABELLED = 14;

type SimNode = TopoNode & SimulationNodeDatum & { r: number };
type SimLink = SimulationLinkDatum<SimNode> & TopoEdge;

export function NetworkMap() {
  const [windowS, setWindowS] = useState(300);
  const { data, error } = usePoll<Topology>(`/topology?window_s=${windowS}&max_nodes=60`, 5000);
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900);
  const sim = useRef<Simulation<SimNode, SimLink> | null>(null);
  const positions = useRef(new Map<string, { x: number; y: number }>());
  const [, setFrame] = useState(0);
  const [nodes, setNodes] = useState<SimNode[]>([]);
  const [links, setLinks] = useState<SimLink[]>([]);
  const [hover, setHover] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const drag = useRef<{ id: string; dx: number; dy: number } | null>(null);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(320, e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Rebuild the simulation whenever the topology changes, keeping positions.
  useEffect(() => {
    if (!data) return;
    const maxBytes = Math.max(1, ...data.nodes.map((n) => n.bytes));
    const anchor = data.nodes.find((n) => n.role === "gateway") ?? data.nodes.find((n) => n.role === "self");
    const ns: SimNode[] = data.nodes.map((n) => {
      const prev = positions.current.get(n.id);
      const sn: SimNode = { ...n, r: 6 + 16 * Math.sqrt(n.bytes / maxBytes), x: prev?.x, y: prev?.y };
      if (anchor && n.id === anchor.id) { sn.fx = width / 2; sn.fy = HEIGHT / 2; }
      return sn;
    });
    const ids = new Set(ns.map((n) => n.id));
    const ls: SimLink[] = data.edges.filter((e) => ids.has(e.source) && ids.has(e.target)).map((e) => ({ ...e }));

    sim.current?.stop();
    const s = forceSimulation<SimNode, SimLink>(ns)
      .force("link", forceLink<SimNode, SimLink>(ls).id((d) => d.id).distance((l) => 120 + (l.source as SimNode).r + (l.target as SimNode).r).strength(0.5))
      .force("charge", forceManyBody().strength(-420))
      .force("center", forceCenter(width / 2, HEIGHT / 2).strength(0.05))
      .force("collide", forceCollide<SimNode>().radius((d) => d.r + 22))
      .alpha(positions.current.size ? 0.3 : 1)
      .on("tick", () => {
        for (const n of ns) {
          n.x = Math.max(n.r + 4, Math.min(width - n.r - 4, n.x ?? 0));
          n.y = Math.max(n.r + 4, Math.min(HEIGHT - n.r - 4, n.y ?? 0));
          positions.current.set(n.id, { x: n.x, y: n.y });
        }
        setFrame((f) => f + 1);
      });
    sim.current = s;
    setNodes(ns);
    setLinks(ls);
    return () => { s.stop(); };
  }, [data, width]);

  const labelled = useMemo(() => {
    const top = [...nodes].sort((a, b) => b.bytes - a.bytes).slice(0, LABELLED).map((n) => n.id);
    return new Set([...top, ...nodes.filter((n) => n.role !== "external").map((n) => n.id)]);
  }, [nodes]);
  const maxEdge = Math.max(1, ...links.map((l) => l.bytes));
  const focus = hover ?? selected;
  const neighbours = useMemo(() => {
    const set = new Set<string>();
    if (!focus) return set;
    for (const l of links) {
      const a = (l.source as SimNode).id, b = (l.target as SimNode).id;
      if (a === focus) set.add(b);
      if (b === focus) set.add(a);
    }
    return set;
  }, [focus, links]);

  const svgPoint = (e: ReactPointerEvent) => {
    const rect = (e.currentTarget as Element).closest("svg")!.getBoundingClientRect();
    return { x: e.clientX - rect.left, y: e.clientY - rect.top };
  };
  const onDown = (e: ReactPointerEvent, n: SimNode) => {
    (e.target as Element).setPointerCapture(e.pointerId);
    const p = svgPoint(e);
    drag.current = { id: n.id, dx: (n.x ?? 0) - p.x, dy: (n.y ?? 0) - p.y };
    sim.current?.alphaTarget(0.2).restart();
  };
  const onMove = (e: ReactPointerEvent, n: SimNode) => {
    if (drag.current?.id !== n.id) return;
    const p = svgPoint(e);
    n.fx = p.x + drag.current.dx;
    n.fy = p.y + drag.current.dy;
  };
  const onUp = (n: SimNode) => {
    if (drag.current?.id === n.id) {
      drag.current = null;
      sim.current?.alphaTarget(0);
    }
  };

  const hovered = nodes.find((n) => n.id === hover);

  return (
    <>
      <Card
        title="Hosts and connections"
        sub={data ? `${data.nodes.length} of ${data.total_hosts} hosts${data.truncated ? " (busiest shown)" : ""}` : undefined}
        actions={
          <div className="segmented">
            {[60, 300, 3600].map((w) => (
              <button key={w} className={windowS === w ? "on" : ""} onClick={() => setWindowS(w)}>
                {w < 3600 ? `${w / 60} min` : "1 hour"}
              </button>
            ))}
          </div>
        }
      >
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8, flexWrap: "wrap" }}>
          <Legend items={(Object.keys(ROLE_LABEL) as TopoNode["role"][]).map((r) => ({ label: ROLE_LABEL[r], color: ROLE_COLOR[r] }))} />
          <span className="muted" style={{ fontSize: 12 }}>Node size = traffic · line width = bytes exchanged · drag to rearrange</span>
        </div>
        <div ref={wrap} style={{ position: "relative" }}>
          {error && <div className="banner error">{error}</div>}
          {data && data.nodes.length === 0 ? <Empty>No hosts seen in this window yet.</Empty> : (
            <svg width={width} height={HEIGHT} role="img" aria-label="Network map of hosts and their connections"
              style={{ display: "block", touchAction: "none" }}>
              {links.map((l) => {
                const a = l.source as SimNode, b = l.target as SimNode;
                const on = focus && (a.id === focus || b.id === focus);
                return (
                  <line key={`${a.id}-${b.id}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                    stroke={on ? "var(--ink-2)" : "var(--axis)"}
                    strokeOpacity={focus && !on ? 0.35 : 1}
                    strokeWidth={1 + 5 * Math.log1p(l.bytes) / Math.log1p(maxEdge)} strokeLinecap="round" />
                );
              })}
              {nodes.map((n) => {
                const dim = focus && n.id !== focus && !neighbours.has(n.id);
                return (
                  <g key={n.id} transform={`translate(${n.x ?? 0},${n.y ?? 0})`} style={{ cursor: "pointer" }}
                    opacity={dim ? 0.35 : 1}
                    onPointerEnter={() => setHover(n.id)} onPointerLeave={() => setHover(null)}
                    onPointerDown={(e) => onDown(e, n)} onPointerMove={(e) => onMove(e, n)} onPointerUp={() => onUp(n)}
                    onClick={() => setSelected(n.id)}>
                    <circle r={n.r + 8} fill="transparent" />
                    <circle r={n.r} fill={ROLE_COLOR[n.role]} stroke="var(--surface)" strokeWidth={2} />
                    {selected === n.id && <circle r={n.r + 4} fill="none" stroke="var(--ink)" strokeWidth={1.5} />}
                    {labelled.has(n.id) && (
                      <text y={n.r + 14} textAnchor="middle" fontSize={11} fill="var(--ink-2)"
                        style={{ paintOrder: "stroke", stroke: "var(--surface)", strokeWidth: 3, pointerEvents: "none" }}>
                        {n.name.length > 26 ? n.name.slice(0, 25) + "…" : n.name}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          )}
          {hovered && (
            <div className="chart-tooltip" style={{ position: "absolute", left: Math.min((hovered.x ?? 0) + 14, width - 220), top: (hovered.y ?? 0) + 10, pointerEvents: "none", width: 210 }}>
              <div style={{ fontWeight: 600 }}>{hovered.name}</div>
              <div className="t mono">{hovered.ip}</div>
              <div className="r"><span>{ROLE_LABEL[hovered.role]}</span></div>
              <div className="r"><span>Sent</span><span className="v">{fmtBytes(hovered.bytes_sent)}</span></div>
              <div className="r"><span>Received</span><span className="v">{fmtBytes(hovered.bytes_recv)}</span></div>
            </div>
          )}
        </div>
      </Card>

      <Card title="Connections" sub="table view of the map, busiest first">
        {!data || data.edges.length === 0 ? <Empty>No connections.</Empty> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Between</th><th>And</th><th>Protocols</th><th className="num">Flows</th><th className="num">Bytes →</th><th className="num">← Bytes</th></tr></thead>
              <tbody>
                {data.edges.slice(0, 25).map((e) => {
                  const name = (ip: string) => data.nodes.find((n) => n.ip === ip)?.name ?? ip;
                  return (
                    <tr key={`${e.source}-${e.target}`} className="clickable" onClick={() => setSelected(e.source)}>
                      <td>{name(e.source)}</td>
                      <td>{name(e.target)}</td>
                      <td>{e.protocols.join(", ")}{e.ports.length ? <span className="muted"> · {e.ports.slice(0, 4).join(", ")}</span> : null}</td>
                      <td className="num">{e.flows}</td>
                      <td className="num">{fmtBytes(e.bytes_ab)}</td>
                      <td className="num">{fmtBytes(e.bytes_ba)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && <HostDrawer ip={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

interface HostDetail {
  ip: string; name: string; hostnames: string[]; mac: string | null; scope: string; is_gateway: boolean;
  first_seen: number; last_seen: number; bytes_sent: number; bytes_recv: number;
  packets_sent: number; packets_recv: number; flows: Flow[]; alerts: Alert[];
}

function HostDrawer({ ip, onClose }: { ip: string; onClose: () => void }) {
  const [h, setH] = useState<HostDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setH(null);
    api.get<HostDetail>(`/hosts/${encodeURIComponent(ip)}`).then(setH).catch((e: Error) => setErr(e.message));
  }, [ip]);

  return (
    <aside className="drawer" role="dialog" aria-label="Host details">
      <header>
        <h3>{h?.name ?? ip}</h3>
        <button className="btn" onClick={onClose} aria-label="Close"><Icon.x /></button>
      </header>
      <div className="body">
        {err && <div className="banner error">{err}</div>}
        {h && (
          <>
            <dl className="kv">
              <dt>IP</dt><dd className="mono">{h.ip}</dd>
              <dt>MAC</dt><dd className="mono">{h.mac ?? "—"}</dd>
              <dt>Role</dt><dd>{h.is_gateway ? "Gateway" : h.scope === "self" ? "This machine" : h.scope === "lan" ? "LAN device" : "External host"}</dd>
              {h.hostnames.length > 0 && <><dt>Names</dt><dd>{h.hostnames.join(", ")}</dd></>}
              <dt>Sent</dt><dd>{fmtBytes(h.bytes_sent)} in {h.packets_sent.toLocaleString()} packets</dd>
              <dt>Received</dt><dd>{fmtBytes(h.bytes_recv)} in {h.packets_recv.toLocaleString()} packets</dd>
              <dt>Last seen</dt><dd>{fmtAgo(h.last_seen)}</dd>
            </dl>
            {h.alerts.length > 0 && (
              <div>
                <div className="section-title">Alerts involving this host</div>
                <div className="stack">
                  {h.alerts.slice(0, 8).map((a) => (
                    <div key={a.alert_id} className="row" style={{ justifyContent: "space-between" }}>
                      <span className="row"><SeverityBadge severity={a.severity} /> {ALERT_LABEL[a.alert_type]}</span>
                      <span className="muted" style={{ fontSize: 12 }}>{fmtAgo(a.timestamp)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div>
              <div className="section-title">Busiest flows</div>
              <table>
                <thead><tr><th>Peer</th><th>State</th><th className="num">Bytes</th></tr></thead>
                <tbody>
                  {h.flows.slice(0, 15).map((f) => {
                    const peerIp = f.src_ip === h.ip ? f.dst_ip : f.src_ip;
                    const peerPort = f.src_ip === h.ip ? f.dst_port : f.src_port;
                    return (
                      <tr key={f.flow_id}>
                        <td className="mono">{endpoint(peerIp, peerPort)} <span className="muted">{f.protocol}</span></td>
                        <td>{f.transport === "TCP" ? f.tcp_state : "—"}</td>
                        <td className="num">{fmtBytes(f.total_bytes)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </aside>
  );
}
