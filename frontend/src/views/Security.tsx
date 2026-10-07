import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { AlertExplanation } from "../components/AlertExplanation";
import { Card, Empty, SeverityBadge, Status, Tile } from "../components/ui";
import { ALERT_LABEL, fmtAgo, fmtDateTime, fmtRate } from "../format";
import { useLive, usePoll } from "../live";
import type { Alert, AlertStatus, Mode, Severity } from "../types";

interface BaselineView { mean: number; std: number; samples: number; ready: boolean }
interface Baselines {
  mode: Mode;
  port_scan: { population: BaselineView; current_threshold: number; tracked_sources: number };
  syn_flood: { population: BaselineView; current_threshold: number; tracked_targets: number };
  traffic_spike: { population: BaselineView; current_threshold_bps: number };
}
interface ArpInfo {
  arp_table: Record<string, string>;
  rebindings: { timestamp: number; ip: string; old_mac: string; new_mac: string; old_mac_idle_s: number | null }[];
}

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function Security() {
  const { alerts, mode, setMode, updateAlert, markAlertsSeen } = useLive();
  const [params, setParams] = useSearchParams();
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("ACTIVE");
  const [modeError, setModeError] = useState<string | null>(null);
  const selectedId = params.get("alert");

  useEffect(() => { markAlertsSeen(); }, [alerts.length, markAlertsSeen]);

  const filtered = useMemo(() => alerts.filter((a) =>
    (!type || a.alert_type === type) && (!severity || a.severity === severity) && (!status || a.status === status),
  ), [alerts, type, severity, status]);
  const selected = alerts.find((a) => a.alert_id === selectedId) ?? null;
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const a of alerts) if (a.status !== "RESOLVED") c[a.severity] = (c[a.severity] ?? 0) + 1;
    return c;
  }, [alerts]);

  const switchMode = async (m: Mode) => {
    setModeError(null);
    try {
      await api.put("/detection/mode", { mode: m });
      setMode(m);
    } catch (e) {
      setModeError((e as Error).message);
    }
  };

  const changeStatus = async (a: Alert, s: AlertStatus) => {
    await api.patch(`/alerts/${a.alert_id}/status`, { status: s });
    updateAlert({ alert_id: a.alert_id, status: s });
  };

  return (
    <>
      <Card
        title="Detection mode"
        actions={
          <div className="segmented" role="radiogroup" aria-label="Detection mode">
            <button className={mode === "static" ? "on" : ""} onClick={() => switchMode("static")} role="radio" aria-checked={mode === "static"}>Static thresholds</button>
            <button className={mode === "adaptive" ? "on" : ""} onClick={() => switchMode("adaptive")} role="radio" aria-checked={mode === "adaptive"}>Adaptive</button>
          </div>
        }
      >
        <p className="ink-2" style={{ margin: 0 }}>
          {mode === "adaptive"
            ? "Adaptive mode compares each signal with an EWMA baseline of what is normal for this network (and for each host once it has history), alerting when it exceeds μ + 3σ. Flow context — half-open handshake ratio, refused connections, whether an old MAC is still alive — separates attacks from look-alikes."
            : "Static mode applies the fixed thresholds from the configuration — the baseline that the adaptive detectors are evaluated against."}
          {" "}Baselines keep learning in both modes, so switching is immediate.
        </p>
        {modeError && <div className="banner error" style={{ marginTop: 8 }}>{modeError}</div>}
      </Card>

      <div className="tiles">
        {SEVERITIES.map((s) => (
          <Tile key={s} label={`${s[0]}${s.slice(1).toLowerCase()}`} value={counts[s] ?? 0} hint="unresolved" />
        ))}
      </div>

      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <Card title="Alerts" sub={`${filtered.length} shown`}>
          <div className="filters" style={{ marginBottom: 12 }}>
            <select className="select" value={type} onChange={(e) => setType(e.target.value)} aria-label="Type">
              <option value="">All types</option>
              {Object.entries(ALERT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s[0] + s.slice(1).toLowerCase()}</option>)}
            </select>
            <select className="select" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
              <option value="">Any status</option>
              <option value="ACTIVE">Active</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
          {filtered.length === 0 ? <Empty>No alerts match. Nothing suspicious detected.</Empty> : (
            <div className="table-wrap" style={{ maxHeight: 620 }}>
              <table>
                <thead><tr><th>Severity</th><th>Alert</th><th>Source → target</th><th>When</th></tr></thead>
                <tbody>
                  {filtered.map((a) => (
                    <tr key={a.alert_id} className={`clickable${a.alert_id === selectedId ? " selected" : ""}`}
                      onClick={() => setParams({ alert: a.alert_id })}>
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{ALERT_LABEL[a.alert_type]}</div>
                        <div className="muted" style={{ fontSize: 12 }}>{a.mode}{a.status !== "ACTIVE" ? ` · ${a.status.toLowerCase()}` : ""}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>{a.source_ip ?? "?"}<br />→ {a.target_ip ?? "network"}</td>
                      <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtAgo(a.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title={selected ? ALERT_LABEL[selected.alert_type] : "Why was this raised?"}
          sub={selected ? fmtDateTime(selected.timestamp) : undefined}
          actions={selected && (
            <div className="row">
              {selected.status === "ACTIVE" && <button className="btn" onClick={() => changeStatus(selected, "ACKNOWLEDGED")}>Acknowledge</button>}
              {selected.status !== "RESOLVED"
                ? <button className="btn" onClick={() => changeStatus(selected, "RESOLVED")}>Resolve</button>
                : <button className="btn" onClick={() => changeStatus(selected, "ACTIVE")}>Reopen</button>}
            </div>
          )}>
          {!selected ? <Empty>Select an alert to see the evidence and the rule that fired.</Empty> : (
            <div className="stack" style={{ gap: 16 }}>
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <SeverityBadge severity={selected.severity} />
                <span className="pill">{selected.status.toLowerCase()}</span>
                <span className="mono ink-2" style={{ fontSize: 12 }}>{selected.source_ip} → {selected.target_ip ?? "network"}</span>
              </div>
              <AlertExplanation alert={selected} />
              <details>
                <summary className="muted" style={{ cursor: "pointer" }}>Raw evidence</summary>
                <dl className="kv" style={{ marginTop: 8 }}>
                  {Object.entries(selected.evidence).map(([k, v]) => (
                    <div key={k} style={{ display: "contents" }}>
                      <dt>{k.replace(/_/g, " ")}</dt>
                      <dd className="mono">{Array.isArray(v) ? v.join(", ") : v === null ? "—" : String(v)}</dd>
                    </div>
                  ))}
                </dl>
              </details>
            </div>
          )}
        </Card>
      </div>

      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <BaselinesCard />
        <ArpCard />
      </div>
    </>
  );
}

function BaselinesCard() {
  const { data } = usePoll<Baselines>("/detection/baselines", 5000);
  if (!data) return <Card title="What normal looks like"><Empty>Loading…</Empty></Card>;
  const row = (label: string, b: BaselineView, threshold: string, unit: string, fmt: (v: number) => string) => (
    <tr>
      <td>{label}</td>
      <td className="num">{b.samples ? `${fmt(b.mean)} ± ${fmt(b.std)}` : "—"} <span className="muted">{unit}</span></td>
      <td className="num">{threshold}</td>
      <td>{b.ready ? <Status kind="good">Learned</Status> : <Status kind="neutral">Warming up ({b.samples})</Status>}</td>
    </tr>
  );
  const n1 = (v: number) => v.toFixed(1);
  return (
    <Card title="What normal looks like" sub="network-wide adaptive baselines, refreshed every 5 s">
      <div className="table-wrap">
        <table>
          <thead><tr><th>Signal</th><th className="num">Baseline μ ± σ</th><th className="num">Alert above</th><th>State</th></tr></thead>
          <tbody>
            {row("Distinct ports per source (5 s)", data.port_scan.population, n1(data.port_scan.current_threshold), "ports", n1)}
            {row("SYN rate per destination", data.syn_flood.population, `${n1(data.syn_flood.current_threshold)}/s`, "SYN/s", n1)}
            {row("Total throughput", data.traffic_spike.population, fmtRate(data.traffic_spike.current_threshold_bps), "", (v) => fmtRate(v))}
          </tbody>
        </table>
      </div>
      <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
        Hosts with enough history are judged against their own baseline instead; samples above μ + σ are clipped before learning so an ongoing attack cannot become "normal".
      </p>
    </Card>
  );
}

function ArpCard() {
  const { data } = usePoll<ArpInfo>("/stats/arp", 10000);
  const entries = Object.entries(data?.arp_table ?? {});
  return (
    <Card title="ARP table" sub={`${entries.length} mappings observed`}>
      {entries.length === 0 ? <Empty>No ARP traffic seen yet.</Empty> : (
        <div className="table-wrap" style={{ maxHeight: 240 }}>
          <table>
            <thead><tr><th>IP</th><th>MAC</th></tr></thead>
            <tbody>{entries.map(([ip, mac]) => <tr key={ip}><td className="mono">{ip}</td><td className="mono">{mac}</td></tr>)}</tbody>
          </table>
        </div>
      )}
      {data && data.rebindings.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 14 }}>Re-bindings (not alerted in adaptive mode)</div>
          <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>The previous MAC had gone silent, which looks like a device leaving and its address being re-assigned rather than two devices claiming one IP.</p>
          <table>
            <thead><tr><th>IP</th><th>Old → new MAC</th><th className="num">Old MAC idle</th></tr></thead>
            <tbody>
              {data.rebindings.slice(-10).reverse().map((r) => (
                <tr key={`${r.ip}-${r.timestamp}`}>
                  <td className="mono">{r.ip}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{r.old_mac} → {r.new_mac}</td>
                  <td className="num">{r.old_mac_idle_s == null ? "never seen" : `${Math.round(r.old_mac_idle_s)} s`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Card>
  );
}
