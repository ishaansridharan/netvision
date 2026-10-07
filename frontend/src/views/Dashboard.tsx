import { Link } from "react-router-dom";
import { TimeSeries } from "../components/TimeSeries";
import {
  BarList, Card, Empty, Meter, SeverityBadge, Status, Tile, componentKind, healthKind,
} from "../components/ui";
import {
  ALERT_LABEL, COMPONENT_LABEL, compact, fmtAgo, fmtMs, fmtRate, fmtTime, mbps, splitRate,
} from "../format";
import { useLive } from "../live";

export function Dashboard() {
  const { snapshot: s, history, alerts, capture } = useLive();

  if (!s) {
    return <Card><Empty>Waiting for the backend… start the server with <code>uvicorn backend.main:app</code>.</Empty></Card>;
  }

  const [dlv, dlu] = splitRate(s.download_bps);
  const [ulv, ulu] = splitRate(s.upload_bps);
  const healthy = healthKind(s.health_score);
  const recent = alerts.slice(0, 6);
  const protocols = Object.entries(s.protocol_dist).slice(0, 7);
  const idle = !capture?.running && s.total_packets === 0;

  return (
    <>
      {idle && (
        <div className="banner">
          <span className="ink-2">No capture running. Use <b>Start capture</b> to monitor a live interface, or replay a recorded capture.</span>
        </div>
      )}

      <div className="grid split">
        <Card title="Network health" sub="weighted over the components with data">
          <div className="row" style={{ gap: 24, alignItems: "flex-start", flexWrap: "wrap" }}>
            <div style={{ minWidth: 140 }}>
              <div className="hero">{s.health_score}<span className="muted" style={{ fontSize: 22, fontWeight: 500 }}>/100</span></div>
              <div style={{ marginTop: 8 }}>
                <Status kind={healthy}>{s.health_score >= 80 ? "Healthy" : s.health_score >= 60 ? "Degraded" : "Poor"}</Status>
              </div>
            </div>
            <div className="stack" style={{ flex: 1, minWidth: 240, gap: 10 }}>
              {s.health.components.map((c) => (
                <div key={c.name}>
                  <div className="row" style={{ justifyContent: "space-between", fontSize: 13 }}>
                    <Status kind={componentKind(c.status)}>{COMPONENT_LABEL[c.name]}</Status>
                    <span className="num ink-2">
                      {c.status === "unknown" ? "no data" : `${c.value} ${c.unit}`}
                      {c.points_lost >= 1 && <span className="muted"> · −{c.points_lost.toFixed(0)} pts</span>}
                    </span>
                  </div>
                  <div style={{ marginTop: 4 }}>
                    <Meter value={c.score ?? 0} kind={componentKind(c.status)} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          {s.health.issues.length > 0 && (
            <ul style={{ margin: "14px 0 0", paddingLeft: 18 }} className="ink-2">
              {s.health.issues.map((i) => <li key={i}>{i}</li>)}
            </ul>
          )}
        </Card>

        <Card title="Recent alerts" actions={<Link to="/security">View all</Link>}>
          {recent.length === 0 ? <Empty>No alerts.</Empty> : (
            <div className="stack" style={{ gap: 10 }}>
              {recent.map((a) => (
                <Link key={a.alert_id} to={`/security?alert=${a.alert_id}`} style={{ color: "inherit", textDecoration: "none" }}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <SeverityBadge severity={a.severity} />
                    <span className="muted" style={{ fontSize: 12 }}>{fmtAgo(a.timestamp)}</span>
                  </div>
                  <div style={{ fontWeight: 600, marginTop: 2 }}>{ALERT_LABEL[a.alert_type]}</div>
                  <div className="ink-2" style={{ fontSize: 13 }}>{a.source_ip ?? "?"} → {a.target_ip ?? "network"}</div>
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="tiles">
        <Tile label="Download" value={dlv} unit={dlu} hint="10 s average" />
        <Tile label="Upload" value={ulv} unit={ulu} hint="10 s average" />
        <Tile label="Packets / s" value={compact(Math.round(s.packets_per_sec))} />
        <Tile label="Latency" value={s.latency_ms == null ? "—" : fmtMs(s.latency_ms)}
          hint={s.rtt_samples ? `median of ${s.rtt_samples} RTTs · p95 ${fmtMs(s.latency_p95_ms)}` : "needs pings or new TCP connections"} />
        <Tile label="Jitter" value={s.jitter_ms == null ? "—" : fmtMs(s.jitter_ms)} hint="RTT variation" />
        <Tile label="Packet loss" value={s.packet_loss_pct == null ? "—" : `${s.packet_loss_pct.toFixed(2)}%`}
          hint={`${s.retransmissions} TCP retransmissions`} />
        <Tile label="Active connections" value={compact(s.active_connections)}
          hint={s.half_open_connections ? `${s.half_open_connections} half-open` : "0 half-open"} />
        <Tile label="Hosts seen" value={compact(s.host_count)} />
      </div>

      <Card title="Traffic" sub="last 5 minutes, Mbit/s">
        {history.length < 2 ? <Empty>Collecting data…</Empty> : (
          <TimeSeries
            data={history.map((h) => ({ t: h.t, download: mbps(h.download), upload: mbps(h.upload) }))}
            x="t"
            series={[
              { key: "download", label: "Download", color: "var(--series-1)" },
              { key: "upload", label: "Upload", color: "var(--series-2)" },
            ]}
           
            formatTooltipX={(v) => fmtTime(v)}
            
          />
        )}
      </Card>

      <div className="grid cols-2">
        <Card title="Protocol distribution" sub="packets, last 10 s">
          {protocols.length === 0 ? <Empty>No traffic.</Empty> : (
            <BarList
              rows={protocols.map(([p, d]) => ({ key: p, label: p, value: d.pct, note: <span className="muted"> · {compact(d.count)}</span> }))}
              format={(v) => `${v.toFixed(1)}%`}
              max={100}
            />
          )}
        </Card>
        <Card title="Top traffic sources" sub="last 10 s">
          {s.top_talkers.length === 0 ? <Empty>No traffic.</Empty> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Host</th><th className="num">Rate</th><th className="num">Share</th></tr></thead>
                <tbody>
                  {s.top_talkers.slice(0, 7).map((t) => (
                    <tr key={t.ip}>
                      <td>
                        <div>{t.name !== t.ip ? t.name : t.ip}</div>
                        {t.name !== t.ip && <div className="muted mono">{t.ip}</div>}
                      </td>
                      <td className="num">{fmtRate(t.bps)}</td>
                      <td className="num" style={{ width: 120 }}>
                        <div className="row" style={{ justifyContent: "flex-end" }}>
                          <span>{t.pct.toFixed(0)}%</span>
                          <div className="bar-track" style={{ width: 50 }}><div className="bar-fill" style={{ width: `${t.pct}%` }} /></div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
