import type { ReactNode } from "react";
import type { Severity } from "../types";

// ── Icons (inline, 16px, currentColor) ─────────────────────────────────
const P = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
  strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };

export const Icon = {
  dashboard: () => <svg {...P}><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></svg>,
  packets: () => <svg {...P}><path d="M4 6h16M4 12h16M4 18h10" /></svg>,
  map: () => <svg {...P}><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="8" r="2.5" /><circle cx="9" cy="18" r="2.5" /><path d="M8.2 7.2l7.5 1.2M7 8.3l1.5 7.3M16.5 10l-5.6 6.4" /></svg>,
  shield: () => <svg {...P}><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z" /></svg>,
  report: () => <svg {...P}><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" /></svg>,
  play: () => <svg {...P}><path d="M7 4l13 8-13 8z" fill="currentColor" /></svg>,
  stop: () => <svg {...P}><rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor" /></svg>,
  sun: () => <svg {...P}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>,
  moon: () => <svg {...P}><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" /></svg>,
  x: () => <svg {...P}><path d="M6 6l12 12M18 6L6 18" /></svg>,
  check: () => <svg {...P}><path d="M5 12l5 5 9-10" /></svg>,
  info: () => <svg {...P}><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7.5v.5" /></svg>,
  pause: () => <svg {...P}><path d="M8 5v14M16 5v14" /></svg>,
  refresh: () => <svg {...P}><path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" /></svg>,
};

// ── Status: colour + icon + label, never colour alone ───────────────────
type StatusKind = "good" | "warning" | "serious" | "critical" | "neutral";

const STATUS_COLOR: Record<StatusKind, string> = {
  good: "var(--good)", warning: "var(--warning)", serious: "var(--serious)",
  critical: "var(--critical)", neutral: "var(--muted)",
};

function StatusGlyph({ kind }: { kind: StatusKind }) {
  const c = STATUS_COLOR[kind];
  if (kind === "good")
    return <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden><circle cx="8" cy="8" r="7" fill={c} /><path d="M4.8 8.2l2.2 2.2 4.2-4.6" stroke="#fff" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" /></svg>;
  if (kind === "critical")
    return <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden><path d="M5.2 1h5.6L15 5.2v5.6L10.8 15H5.2L1 10.8V5.2z" fill={c} /><path d="M8 4.5v4.2M8 11v.3" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" /></svg>;
  if (kind === "neutral")
    return <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden><circle cx="8" cy="8" r="6.5" fill="none" stroke={c} strokeWidth="1.6" /><path d="M8 7.2v4M8 4.8v.2" stroke={c} strokeWidth="1.6" strokeLinecap="round" /></svg>;
  return <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden><path d="M8 1.2L15.2 14H.8z" fill={c} /><path d="M8 6v3.6M8 11.6v.2" stroke="#0b0b0b" strokeWidth="1.6" strokeLinecap="round" /></svg>;
}

export function Status({ kind, children }: { kind: StatusKind; children: ReactNode }) {
  return <span className="status"><StatusGlyph kind={kind} />{children}</span>;
}

const SEVERITY_KIND: Record<Severity, StatusKind> = {
  LOW: "neutral", MEDIUM: "warning", HIGH: "serious", CRITICAL: "critical",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Status kind={SEVERITY_KIND[severity]}>{severity[0] + severity.slice(1).toLowerCase()}</Status>;
}

export function healthKind(score: number | null | undefined): StatusKind {
  if (score == null) return "neutral";
  if (score >= 80) return "good";
  if (score >= 60) return "warning";
  if (score >= 40) return "serious";
  return "critical";
}

export function componentKind(status: string): StatusKind {
  return ({ good: "good", degraded: "warning", bad: "critical", unknown: "neutral" } as Record<string, StatusKind>)[status] ?? "neutral";
}

// ── Layout primitives ───────────────────────────────────────────────────
export function Card({ title, sub, actions, children, className = "" }: {
  title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {sub && <span className="sub">{sub}</span>}
          <span className="spacer" />
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Tile({ label, value, unit, hint }: { label: string; value: ReactNode; unit?: string; hint?: ReactNode }) {
  return (
    <div className="tile">
      <div className="label">{label}</div>
      <div className="value">{value}{unit && <span className="unit">{unit}</span>}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export interface LegendItem { label: string; color: string; shape?: "swatch" | "line" }

export function Legend({ items }: { items: LegendItem[] }) {
  return (
    <div className="legend">
      {items.map((i) => (
        <span className="key" key={i.label}>
          <span className={i.shape === "line" ? "line" : "swatch"} style={{ background: i.color }} />
          {i.label}
        </span>
      ))}
    </div>
  );
}

/** Horizontal bar list — one series, value at the tip, label on the left. */
export function BarList({ rows, format, max }: {
  rows: { key: string; label: ReactNode; value: number; note?: ReactNode }[];
  format: (v: number) => string;
  max?: number;
}) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="stack" style={{ gap: 10 }}>
      {rows.map((r) => (
        <div key={r.key}>
          <div className="row" style={{ justifyContent: "space-between", fontSize: 13, marginBottom: 4 }}>
            <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.label}</span>
            <span className="num ink-2" style={{ whiteSpace: "nowrap", paddingLeft: 8 }}>{format(r.value)}{r.note}</span>
          </div>
          <div className="bar-track"><div className="bar-fill" style={{ width: `${(r.value / top) * 100}%` }} /></div>
        </div>
      ))}
    </div>
  );
}

/** Meter: fill carries severity, track is a lighter step. */
export function Meter({ value, max = 1, kind }: { value: number; max?: number; kind: StatusKind }) {
  const pct = Math.max(0, Math.min(1, value / max)) * 100;
  return (
    <div className="bar-track" style={{ height: 6 }}>
      <div className="bar-fill" style={{ width: `${pct}%`, background: STATUS_COLOR[kind] }} />
    </div>
  );
}
