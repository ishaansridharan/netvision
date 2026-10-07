import { useState } from "react";
import { TimeSeries } from "../components/TimeSeries";
import { BarList, Card, Empty, SeverityBadge, Status, Tile, componentKind, healthKind } from "../components/ui";
import {
  ALERT_LABEL, COMPONENT_LABEL, compact, fmtBytes, fmtDateTime, fmtDuration, fmtMs, fmtRate, fmtTime, mbps,
} from "../format";
import { usePoll } from "../live";
import type { Alert, HealthComponent } from "../types";

interface TrendPoint {
  timestamp: number; download_bps: number; upload_bps: number; lan_bps: number;
  packets_per_sec: number; latency_ms: number | null; health_score: number | null; active_connections: number;
}
interface Summary {
  range: { start: number; end: number; minutes: number; samples?: number };
  message?: string;
  traffic?: { total_bytes: number; total_packets: number; avg_bps: number; peak_bps: number; peak_at: number };
  latency?: { avg_ms: number | null; max_ms: number | null };
  health?: {
    avg: number | null; min: number | null; latest: number | null; degraded_seconds: number;
    recurring_issues: { component: string; seconds: number; latest_reason: string }[];
    frequent_culprits: { ip: string; seconds: number }[];
  };
  protocols?: { protocol: string; packets: number; pct: number }[];
  top_devices?: { ip: string; name: string; approx_bytes: number; pct: number }[];
  top_destinations?: { ip: string; name: string; approx_bytes: number; pct: number }[];
  services: { completed_flows: number; top_services: { port: number | null; transport: string; flows: number; bytes: number }[] };
  trend?: TrendPoint[];
  alerts: { total: number; by_type: Record<string, number>; by_severity: Record<string, number>; recent: Alert[] };
}
interface Diagnosis {
  now: { health_score: number; headline: string; causes: HealthComponent[]; chain: string[]; related_alerts: Alert[] } | null;
  degraded_periods: { start: number; end: number; duration_s: number; min_score: number; main_issue: string | null }[];
}
interface Pipeline {
  received: number; processed: number; dropped: number; unparsed: number; drop_rate_pct: number;
  queue_capacity: number; max_queue_depth: number;
  current: { processed_pps?: number; capacity_pps?: number | null; avg_processing_us?: number | null; queue_depth?: number };
  history: { timestamp: number; processed_pps: number; received_pps: number; dropped_pps: number }[];
}

const RANGES = [15, 60, 360, 1440];

export function Reports() {
  const [minutes, setMinutes] = useState(60);
  const { data: s, error } = usePoll<Summary>(`/reports/summary?minutes=${minutes}`, 15000);

  return (
    <>
      <DiagnosisCard />

      <div className="row" style={{ justifyContent: "space-between", flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>History</h2>
        <div className="segmented" aria-label="Time range">
          {RANGES.map((m) => (
            <button key={m} className={m === minutes ? "on" : ""} onClick={() => setMinutes(m)}>
              {m < 60 ? `${m} min` : `${m / 60} h`}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="banner error">{error}</div>}
      {!s ? <Card><Empty>Loading…</Empty></Card> : !s.traffic ? (
        <Card><Empty>{s.message ?? "No stored data for this range yet."}</Empty></Card>
      ) : (
        <>
          <div className="tiles">
            <Tile label="Total traffic" value={fmtBytes(s.traffic.total_bytes)} hint={`${compact(s.traffic.total_packets)} packets`} />
            <Tile label="Average rate" value={fmtRate(s.traffic.avg_bps)} />
            <Tile label="Peak rate" value={fmtRate(s.traffic.peak_bps)} hint={`at ${fmtTime(s.traffic.peak_at)}`} />
            <Tile label="Average latency" value={fmtMs(s.latency?.avg_ms)} hint={s.latency?.max_ms != null ? `max ${fmtMs(s.latency.max_ms)}` : undefined} />
            <Tile label="Average health" value={s.health?.avg ?? "—"} hint={s.health?.min != null ? `lowest ${s.health.min}` : undefined} />
            <Tile label="Time degraded" value={fmtDuration(s.health?.degraded_seconds ?? 0)} hint="health below 70" />
            <Tile label="Alerts" value={s.alerts.total} />
            <Tile label="Completed flows" value={compact(s.services.completed_flows)} />
          </div>

          <Card title="Traffic trend" sub="Mbit/s">
            <TimeSeries
              data={(s.trend ?? []).map((p) => ({ t: p.timestamp, download: mbps(p.download_bps), upload: mbps(p.upload_bps) }))}
              x="t" height={200}
              series={[
                { key: "download", label: "Download", color: "var(--series-1)" },
                { key: "upload", label: "Upload", color: "var(--series-2)" },
              ]}
              formatTooltipX={fmtDateTime}
              
            />
          </Card>

          <div className="grid cols-2">
            <Card title="Latency trend" sub="median RTT, ms">
              <TimeSeries
                data={(s.trend ?? []).map((p) => ({ t: p.timestamp, latency: p.latency_ms }))}
                x="t" height={170} series={[{ key: "latency", label: "Latency", color: "var(--series-1)" }]}
                formatTooltipX={fmtDateTime}
              />
            </Card>
            <Card title="Health trend" sub="score / 100">
              <TimeSeries
                data={(s.trend ?? []).map((p) => ({ t: p.timestamp, health: p.health_score }))}
                x="t" height={170} series={[{ key: "health", label: "Health", color: "var(--series-1)" }]}
                formatTooltipX={fmtDateTime}
                yDomain={[0, 100]}
              />
            </Card>
          </div>

          <div className="grid cols-3">
            <Card title="Protocol mix" sub="share of packets">
              <BarList rows={(s.protocols ?? []).slice(0, 7).map((p) => ({ key: p.protocol, label: p.protocol, value: p.pct }))}
                format={(v) => `${v.toFixed(1)}%`} max={100} />
            </Card>
            <Card title="Top devices" sub="by traffic sent (approx.)">
              <RankTable rows={s.top_devices ?? []} />
            </Card>
            <Card title="Top destinations" sub="by traffic received (approx.)">
              <RankTable rows={s.top_destinations ?? []} />
            </Card>
          </div>

          <div className="grid cols-2" style={{ alignItems: "start" }}>
            <Card title="Busiest services" sub="completed flows by destination port">
              {s.services.top_services.length === 0 ? <Empty>No completed flows stored yet.</Empty> : (
                <table>
                  <thead><tr><th>Service</th><th className="num">Flows</th><th className="num">Bytes</th></tr></thead>
                  <tbody>
                    {s.services.top_services.map((x) => (
                      <tr key={`${x.transport}-${x.port}`}>
                        <td className="mono">{x.transport}/{x.port ?? "—"}</td>
                        <td className="num">{x.flows.toLocaleString()}</td>
                        <td className="num">{fmtBytes(x.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Alert history" sub={`${s.alerts.total} in range`}>
              {s.alerts.total === 0 ? <Empty>No alerts in this range.</Empty> : (
                <>
                  <BarList rows={Object.entries(s.alerts.by_type).map(([k, v]) => ({ key: k, label: ALERT_LABEL[k] ?? k, value: v }))}
                    format={(v) => String(v)} />
                  <table style={{ marginTop: 12 }}>
                    <tbody>
                      {s.alerts.recent.slice(0, 8).map((a) => (
                        <tr key={a.alert_id}>
                          <td><SeverityBadge severity={a.severity} /></td>
                          <td>{ALERT_LABEL[a.alert_type]}</td>
                          <td className="mono" style={{ fontSize: 12 }}>{a.source_ip}</td>
                          <td className="muted num" style={{ whiteSpace: "nowrap" }}>{fmtDateTime(a.timestamp)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </Card>
          </div>
        </>
      )}

      <PipelineCard />
      <EvaluationCard />
    </>
  );
}

function RankTable({ rows }: { rows: { ip: string; name: string; approx_bytes: number; pct: number }[] }) {
  if (!rows.length) return <Empty>No data.</Empty>;
  return (
    <table>
      <tbody>
        {rows.slice(0, 7).map((r) => (
          <tr key={r.ip}>
            <td>
              <div style={{ overflow: "hidden", textOverflow: "ellipsis", maxWidth: 180, whiteSpace: "nowrap" }}>{r.name}</div>
              {r.name !== r.ip && <div className="muted mono">{r.ip}</div>}
            </td>
            <td className="num">{fmtBytes(r.approx_bytes)}</td>
            <td className="num muted">{r.pct.toFixed(0)}%</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DiagnosisCard() {
  const { data } = usePoll<Diagnosis>("/reports/diagnosis?minutes=60", 5000);
  const now = data?.now;
  return (
    <Card title="Why is my network slow?" sub="live diagnosis from the health breakdown">
      {!now ? <Empty>No data yet.</Empty> : (
        <div className="stack" style={{ gap: 14 }}>
          <div className="row" style={{ gap: 14, alignItems: "flex-start" }}>
            <div className="hero" style={{ fontSize: 44 }}>{now.health_score}</div>
            <div className="stack" style={{ gap: 6 }}>
              <Status kind={healthKind(now.health_score)}>{now.health_score >= 80 ? "Healthy" : now.health_score >= 60 ? "Degraded" : "Poor"}</Status>
              <div style={{ fontSize: 15 }}>{now.headline}</div>
            </div>
          </div>

          {now.chain.length > 0 && (
            <div className="row" style={{ flexWrap: "wrap", gap: 6 }}>
              {now.chain.map((step, i) => (
                <span key={step} className="row" style={{ gap: 6 }}>
                  {i > 0 && <span className="muted" aria-hidden>→</span>}
                  <span className="pill" style={{ fontSize: 13, color: "var(--ink)" }}>{step}</span>
                </span>
              ))}
            </div>
          )}

          {now.causes.length > 0 && (
            <table>
              <thead><tr><th>Factor</th><th className="num">Points lost</th><th>Why</th></tr></thead>
              <tbody>
                {now.causes.map((c) => (
                  <tr key={c.name}>
                    <td><Status kind={componentKind(c.status)}>{COMPONENT_LABEL[c.name]}</Status></td>
                    <td className="num">−{c.points_lost.toFixed(0)}</td>
                    <td className="ink-2">{c.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {data && data.degraded_periods.length > 0 && (
            <div>
              <div className="section-title">Degraded periods, last hour</div>
              <table>
                <thead><tr><th>From</th><th className="num">Duration</th><th className="num">Lowest score</th><th>Main issue</th></tr></thead>
                <tbody>
                  {data.degraded_periods.slice().reverse().map((p) => (
                    <tr key={p.start}>
                      <td>{fmtTime(p.start)}</td>
                      <td className="num">{fmtDuration(p.duration_s)}</td>
                      <td className="num">{p.min_score}</td>
                      <td>{p.main_issue ? COMPONENT_LABEL[p.main_issue] ?? p.main_issue : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function PipelineCard() {
  const { data: m } = usePoll<Pipeline>("/metrics/pipeline?history=120", 2000);
  if (!m) return null;
  return (
    <Card title="Processing performance" sub="live capture path: queue → parser → analysis">
      <div className="tiles" style={{ marginBottom: 12 }}>
        <Tile label="Analysed now" value={compact(Math.round(m.current.processed_pps ?? 0))} unit="pkt/s" />
        <Tile label="Estimated capacity" value={m.current.capacity_pps ? compact(m.current.capacity_pps) : "—"} unit="pkt/s"
          hint={m.current.avg_processing_us != null ? `${m.current.avg_processing_us} µs per packet` : "no traffic yet"} />
        <Tile label="Drop rate" value={`${m.drop_rate_pct.toFixed(2)}%`} hint={`${m.dropped.toLocaleString()} of ${m.received.toLocaleString()} packets`} />
        <Tile label="Queue" value={`${m.current.queue_depth ?? 0}`} hint={`peak ${m.max_queue_depth.toLocaleString()} / ${m.queue_capacity.toLocaleString()}`} />
      </div>
      {m.history.length > 1 && (
        <TimeSeries
          data={m.history.map((h) => ({ t: h.timestamp, processed: h.processed_pps }))}
          x="t" height={140} series={[{ key: "processed", label: "Packets analysed / s", color: "var(--series-1)" }]}
          formatY={(v) => compact(Math.round(v))}
        />
      )}
    </Card>
  );
}

interface EvalMetrics {
  precision: number | null; recall: number | null; f1: number | null; fpr: number | null;
  latency_median_s: number | null; incidents: number; detected: number; true_positives: number; false_positives: number;
}
interface Evaluation {
  available: boolean; message?: string; name?: string; generated_at_iso?: string;
  cases?: { name: string; packets: number; duration_s: number; incidents: unknown[] }[];
  results?: Record<"static" | "adaptive", { overall: EvalMetrics; per_type: Record<string, EvalMetrics>; false_alerts_per_normal_hour: number | null }>;
  performance?: { parse_pps: number; pipeline_pps_adaptive: number; end_to_end_pps_adaptive: number };
  charts?: { quality: string; fpr: string; latency: string; timelines: string[] };
}

function EvaluationCard() {
  const { data } = usePoll<Evaluation>("/reports/evaluation", 0);
  if (!data) return null;
  if (!data.available || !data.results) {
    return (
      <Card title="Evaluation: static vs adaptive">
        <Empty>No evaluation run yet. Record a labelled capture and run <code>python -m evaluation.run_eval captures/&lt;file&gt;.pcap</code>.</Empty>
      </Card>
    );
  }
  const r = data.results;
  const f = (v: number | null, pct = false) => (v == null ? "—" : pct ? `${(v * 100).toFixed(1)}%` : v.toFixed(2));
  const rows: [string, (m: EvalMetrics) => string][] = [
    ["Precision", (m) => f(m.precision)], ["Recall", (m) => f(m.recall)], ["F1-score", (m) => f(m.f1)],
    ["False-positive rate", (m) => f(m.fpr, true)],
    ["Median detection latency", (m) => (m.latency_median_s == null ? "—" : `${m.latency_median_s.toFixed(1)} s`)],
    ["Incidents detected", (m) => `${m.detected} / ${m.incidents}`],
    ["False positives", (m) => String(m.false_positives)],
  ];
  return (
    <Card title="Evaluation: static vs adaptive"
      sub={`${data.name} · ${data.cases?.length ?? 0} capture(s), ${(data.cases ?? []).reduce((a, c) => a + c.packets, 0).toLocaleString()} packets · ${data.generated_at_iso}`}>
      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <table>
          <thead><tr><th>Metric</th><th className="num">Static</th><th className="num">Adaptive</th></tr></thead>
          <tbody>
            {rows.map(([label, fn]) => (
              <tr key={label}><td>{label}</td><td className="num">{fn(r.static.overall)}</td><td className="num">{fn(r.adaptive.overall)}</td></tr>
            ))}
            <tr><td>False alerts per normal hour</td><td className="num">{r.static.false_alerts_per_normal_hour ?? "—"}</td><td className="num">{r.adaptive.false_alerts_per_normal_hour ?? "—"}</td></tr>
          </tbody>
        </table>
        {data.charts && (
          <img src={`/evaluation-results/${data.charts.quality}`} alt="Precision, recall and F1 for static and adaptive detection"
            style={{ width: "100%", borderRadius: 8, border: "1px solid var(--border)" }} />
        )}
      </div>
      {data.charts && (
        <div className="grid cols-2" style={{ marginTop: 16 }}>
          <img src={`/evaluation-results/${data.charts.fpr}`} alt="False-positive rate per detector" style={{ width: "100%", borderRadius: 8, border: "1px solid var(--border)" }} />
          <img src={`/evaluation-results/${data.charts.latency}`} alt="Median detection latency per attack type" style={{ width: "100%", borderRadius: 8, border: "1px solid var(--border)" }} />
        </div>
      )}
      {data.performance && (
        <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
          Offline processing: parser {data.performance.parse_pps.toLocaleString()} pkt/s, adaptive analysis {data.performance.pipeline_pps_adaptive.toLocaleString()} pkt/s, end to end {data.performance.end_to_end_pps_adaptive.toLocaleString()} pkt/s.
        </p>
      )}
    </Card>
  );
}
