// One WebSocket per tab feeding every view.  On (re)connect the buffers are
// seeded from REST so a view opened mid-session isn't empty.

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, wsUrl } from "./api";
import type { Alert, CaptureStatus, LiveUpdate, Mode, Packet, PipelineMetrics, Snapshot } from "./types";

const HISTORY = 300;   // 5 minutes of 1-second snapshots
const PACKETS = 1000;
const ALERTS = 500;

export interface HistoryPoint {
  t: number;
  download: number;
  upload: number;
  lan: number;
  pps: number;
  latency: number | null;
  health: number;
  connections: number;
}

interface LiveState {
  connected: boolean;
  snapshot: Snapshot | null;
  history: HistoryPoint[];
  packets: Packet[];          // newest first
  alerts: Alert[];            // newest first
  capture: CaptureStatus | null;
  pipeline: PipelineMetrics;
  mode: Mode;
  unseenAlerts: number;
}

interface LiveApi extends LiveState {
  markAlertsSeen: () => void;
  updateAlert: (a: Pick<Alert, "alert_id"> & Partial<Alert>) => void;
  setMode: (m: Mode) => void;
  refreshCapture: () => Promise<void>;
}

const Ctx = createContext<LiveApi | null>(null);

function toPoint(s: Snapshot): HistoryPoint {
  return {
    t: s.timestamp,
    download: s.download_bps,
    upload: s.upload_bps,
    lan: s.lan_bps,
    pps: s.packets_per_sec,
    latency: s.latency_ms,
    health: s.health_score,
    connections: s.active_connections,
  };
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveState>({
    connected: false, snapshot: null, history: [], packets: [], alerts: [],
    capture: null, pipeline: {}, mode: "adaptive", unseenAlerts: 0,
  });
  const retry = useRef(0);

  const seed = useCallback(async () => {
    try {
      const [hist, pk, al, cap, cur] = await Promise.all([
        api.get<{ snapshots: Snapshot[] }>(`/stats/history?limit=${HISTORY}&compact=true`),
        api.get<{ packets: Packet[] }>("/packets?limit=300"),
        api.get<{ alerts: Alert[] }>(`/alerts?limit=${ALERTS}`),
        api.get<CaptureStatus>("/capture/status"),
        api.get<{ snapshot: Snapshot | null }>("/stats/current"),
      ]);
      setState((s) => ({
        ...s,
        history: hist.snapshots.map(toPoint),
        packets: pk.packets,
        alerts: al.alerts,
        capture: cap,
        snapshot: cur.snapshot ?? s.snapshot,
      }));
    } catch {
      /* backend not up yet — the socket retry loop will try again */
    }
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: number | undefined;
    let closed = false;

    const connect = () => {
      ws = new WebSocket(wsUrl("/ws/live"));
      ws.onopen = () => {
        retry.current = 0;
        setState((s) => ({ ...s, connected: true }));
        ws?.send(JSON.stringify({ packet_limit: 200 }));
        seed();
      };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data) as LiveUpdate;
        setState((s) => {
          const next: LiveState = {
            ...s,
            capture: msg.capture,
            pipeline: msg.pipeline,
            mode: msg.detection_mode,
          };
          if (msg.stats) {
            next.snapshot = msg.stats;
            next.history = [...s.history, toPoint(msg.stats)].slice(-HISTORY);
          }
          if (msg.packets.length) {
            next.packets = [...msg.packets, ...s.packets].slice(0, PACKETS);
          }
          if (msg.new_alerts.length) {
            const fresh = [...msg.new_alerts].reverse();
            next.alerts = [...fresh, ...s.alerts].slice(0, ALERTS);
            next.unseenAlerts = s.unseenAlerts + fresh.length;
          }
          return next;
        });
      };
      ws.onclose = () => {
        setState((s) => ({ ...s, connected: false }));
        if (closed) return;
        const delay = Math.min(10_000, 500 * 2 ** retry.current++);
        timer = window.setTimeout(connect, delay);
      };
      ws.onerror = () => ws?.close();
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(timer);
      ws?.close();
    };
  }, [seed]);

  const value: LiveApi = {
    ...state,
    markAlertsSeen: useCallback(() => setState((s) => ({ ...s, unseenAlerts: 0 })), []),
    updateAlert: useCallback(
      (a) => setState((s) => ({
        ...s,
        alerts: s.alerts.map((x) => (x.alert_id === a.alert_id ? { ...x, ...a } : x)),
      })),
      [],
    ),
    setMode: useCallback((m: Mode) => setState((s) => ({ ...s, mode: m })), []),
    refreshCapture: useCallback(async () => {
      const cap = await api.get<CaptureStatus>("/capture/status");
      setState((s) => ({ ...s, capture: cap }));
    }, []),
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useLive(): LiveApi {
  const v = useContext(Ctx);
  if (!v) throw new Error("useLive outside LiveProvider");
  return v;
}

/** Poll a REST endpoint every *ms* while mounted. */
export function usePoll<T>(path: string | null, ms: number): { data: T | null; error: string | null; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!path) return;
    let alive = true;
    const load = () =>
      api.get<T>(path)
        .then((d) => { if (alive) { setData(d); setError(null); } })
        .catch((e: Error) => { if (alive) setError(e.message); });
    load();
    const id = ms > 0 ? window.setInterval(load, ms) : undefined;
    return () => { alive = false; window.clearInterval(id); };
  }, [path, ms, tick]);
  return { data, error, reload: () => setTick((t) => t + 1) };
}
