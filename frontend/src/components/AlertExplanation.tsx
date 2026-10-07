// "Why did this alert fire?" — renders Alert.explanation.

import type { Alert, Explanation } from "../types";
import { fmtRate } from "../format";

function isExplanation(e: Alert["explanation"]): e is Explanation {
  return Boolean(e && "summary" in e);
}

function fmtValue(alert: Alert, v: number): string {
  if (alert.alert_type === "TRAFFIC_SPIKE") return fmtRate(v);
  if (Math.abs(v) >= 100) return Math.round(v).toLocaleString();
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

export function AlertExplanation({ alert }: { alert: Alert }) {
  const ex = alert.explanation;
  if (!isExplanation(ex)) {
    return <p className="ink-2">{alert.description}</p>;
  }

  // Observed vs threshold on one scale; the threshold is a marker on the track.
  const scaleMax = Math.max(ex.observed, ex.threshold) * 1.15 || 1;
  const obsPct = (ex.observed / scaleMax) * 100;
  const thrPct = (ex.threshold / scaleMax) * 100;
  const meanPct = ex.baseline ? (ex.baseline.mean / scaleMax) * 100 : null;
  const showScale = alert.alert_type !== "ARP_ANOMALY" && ex.observed >= 0;

  return (
    <div className="stack" style={{ gap: 14 }}>
      <p style={{ margin: 0, fontSize: 15, lineHeight: 1.5 }}>{ex.summary}</p>

      {showScale && (
        <div>
          <div className="section-title">{ex.metric}</div>
          <div style={{ position: "relative", height: 34, marginTop: 6 }}>
            <div className="bar-track" style={{ position: "absolute", top: 12, left: 0, right: 0, height: 10 }}>
              <div className="bar-fill" style={{ width: `${obsPct}%`, background: "var(--serious)" }} />
            </div>
            {meanPct != null && (
              <div title="Baseline mean" style={{ position: "absolute", left: `${meanPct}%`, top: 8, width: 2, height: 18, background: "var(--ink-2)" }} />
            )}
            <div title="Threshold" style={{ position: "absolute", left: `${thrPct}%`, top: 4, width: 2, height: 26, background: "var(--ink)" }} />
          </div>
          <div className="row" style={{ justifyContent: "space-between", fontSize: 12 }}>
            <span><span className="status"><span className="dot" style={{ background: "var(--serious)", borderRadius: 3 }} />Observed {fmtValue(alert, ex.observed)}</span></span>
            {ex.baseline && <span className="ink-2">Normal μ {fmtValue(alert, ex.baseline.mean)}</span>}
            <span className="ink-2">Threshold {fmtValue(alert, ex.threshold)}</span>
          </div>
        </div>
      )}

      <dl className="kv">
        <dt>Rule</dt><dd><code>{ex.rule}</code></dd>
        <dt>Mode</dt><dd>{alert.mode === "adaptive" ? "Adaptive (EWMA baseline + flow context)" : "Static (fixed threshold)"}</dd>
        {ex.baseline && (
          <>
            <dt>Baseline</dt>
            <dd>
              μ = {fmtValue(alert, ex.baseline.mean)}, σ = {fmtValue(alert, ex.baseline.std)}
              {" "}({ex.baseline.samples} samples, {ex.baseline.scope === "per-host" ? "this host's own history" : "network-wide"})
            </dd>
          </>
        )}
        {ex.z_score != null && (<><dt>z-score</dt><dd>{ex.z_score.toFixed(1)} σ above normal</dd></>)}
      </dl>

      {ex.factors.length > 0 && (
        <div>
          <div className="section-title">Supporting evidence</div>
          <ul style={{ margin: 0, paddingLeft: 18 }} className="stack">
            {ex.factors.map((f) => <li key={f}>{f}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
