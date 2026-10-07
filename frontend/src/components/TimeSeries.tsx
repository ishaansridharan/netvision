// Line chart with a crosshair + tooltip, styled to the chart specs:
// 2px lines, hairline solid grid on one axis, legend for ≥ 2 series,
// 10% area wash for single-series charts, one y-axis only.

import {
  Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Legend } from "./ui";

export interface Series {
  key: string;
  label: string;
  color: string;
}

type Row = Record<string, number | null>;

interface Props {
  data: Row[];
  x: string;
  series: Series[];
  height?: number;
  formatY?: (v: number) => string;
  formatX?: (v: number) => string;
  formatTooltipX?: (v: number) => string;
  yDomain?: [number | "auto" | "dataMin", number | "auto" | "dataMax"];
}

interface TipProps {
  active?: boolean;
  label?: number;
  payload?: { dataKey: string; value: number | null; color: string }[];
}

/** Tick values are already "nice" numbers; print them without padding zeros. */
export const plainNumber = (v: number) => String(Number(v.toFixed(2)));

function clockFormat(span: number): (v: number) => string {
  // Minute-only labels repeat on short spans, so show seconds below 15 min.
  const opts: Intl.DateTimeFormatOptions = span < 900
    ? { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }
    : { hour: "2-digit", minute: "2-digit", hour12: false };
  return (v) => new Date(v * 1000).toLocaleTimeString(undefined, opts);
}

export function TimeSeries({ data, x, series, height = 220, formatY = plainNumber, formatX, formatTooltipX, yDomain }: Props) {
  const single = series.length === 1;
  const span = data.length > 1 ? (data[data.length - 1][x] ?? 0) - (data[0][x] ?? 0) : 0;
  formatX = formatX ?? clockFormat(span);

  const Tip = ({ active, label, payload }: TipProps) => {
    if (!active || !payload?.length || label == null) return null;
    return (
      <div className="chart-tooltip">
        <div className="t">{(formatTooltipX ?? formatX)(label)}</div>
        {series.map((s) => {
          const p = payload.find((q) => q.dataKey === s.key);
          return (
            <div className="r" key={s.key}>
              <span className="line" style={{ width: 12, height: 2, background: s.color, borderRadius: 1 }} />
              <span>{s.label}</span>
              <span className="v">{p?.value == null ? "—" : formatY(p.value)}</span>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div>
      {!single && <div style={{ marginBottom: 8 }}><Legend items={series.map((s) => ({ ...s, shape: "line" }))} /></div>}
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" strokeWidth={1} />
          <XAxis
            dataKey={x} type="number" domain={["dataMin", "dataMax"]} scale="time"
            tickFormatter={formatX} stroke="var(--axis)" tick={{ fill: "var(--muted)", fontSize: 11 }}
            tickLine={false} minTickGap={48}
          />
          <YAxis
            tickFormatter={formatY} stroke="none" tick={{ fill: "var(--muted)", fontSize: 11 }}
            width={64} domain={yDomain ?? [0, "auto"]} allowDecimals
          />
          <Tooltip content={<Tip />} cursor={{ stroke: "var(--axis)", strokeWidth: 1 }} isAnimationActive={false} />
          {single && (
            <Area dataKey={series[0].key} stroke="none" fill={series[0].color} fillOpacity={0.1}
              isAnimationActive={false} />
          )}
          {series.map((s) => (
            <Line
              key={s.key} dataKey={s.key} stroke={s.color} strokeWidth={2} dot={false}
              activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2, fill: s.color }}
              isAnimationActive={false} strokeLinecap="round" strokeLinejoin="round"
            />
          ))}
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
