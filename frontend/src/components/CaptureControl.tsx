import { useEffect, useState } from "react";
import { api } from "../api";
import { useLive } from "../live";
import { fmtDuration } from "../format";
import type { NetInterface } from "../types";
import { Icon } from "./ui";

type Source = "live" | "replay";

export function CaptureControl() {
  const { capture, refreshCapture, connected } = useLive();
  const [open, setOpen] = useState(false);
  const [source, setSource] = useState<Source>("live");
  const [ifaces, setIfaces] = useState<NetInterface[]>([]);
  const [iface, setIface] = useState("");
  const [filter, setFilter] = useState("");
  const [files, setFiles] = useState<{ name: string; size_bytes: number }[]>([]);
  const [file, setFile] = useState("");
  const [speed, setSpeed] = useState(1);
  const [loop, setLoop] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    api.get<{ interfaces: NetInterface[]; default: string | null }>("/interfaces").then((r) => {
      setIfaces(r.interfaces);
      setIface((cur) => cur || r.default || r.interfaces[0]?.name || "");
    }).catch(() => {});
    api.get<{ files: { name: string; size_bytes: number }[] }>("/capture/files").then((r) => {
      setFiles(r.files);
      setFile((cur) => cur || r.files[0]?.name || "");
    }).catch(() => {});
  }, [open]);

  const running = capture?.running ?? false;

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      if (source === "live") {
        await api.post("/capture/start", { interface: iface || null, bpf_filter: filter || null });
      } else {
        await api.post("/capture/replay", { file, speed, loop });
      }
      setOpen(false);
      await refreshCapture();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    try {
      await api.post("/capture/stop");
      await refreshCapture();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ position: "relative" }}>
      <div className="row">
        <span className="status" title={capture?.error ?? undefined}>
          <span className="dot" style={{ background: !connected ? "var(--critical)" : running ? "var(--good)" : "var(--muted)" }} />
          {!connected ? "Backend offline" : running
            ? `${capture?.source === "replay" ? "Replaying" : "Capturing"} · ${capture?.source === "replay" ? capture.replay_file : capture?.interface} · ${fmtDuration(capture?.uptime_seconds ?? 0)}`
            : "Idle"}
        </span>
        {running ? (
          <button className="btn danger" onClick={stop} disabled={busy}><Icon.stop /> Stop</button>
        ) : (
          <button className="btn primary" onClick={() => setOpen((o) => !o)} disabled={!connected}>
            <Icon.play /> Start capture
          </button>
        )}
      </div>

      {open && !running && (
        <div className="card" style={{ position: "absolute", right: 0, top: "calc(100% + 8px)", width: 360, zIndex: 20, boxShadow: "0 8px 24px rgba(0,0,0,.14)" }}>
          <div className="stack" style={{ gap: 12 }}>
            <div className="segmented" role="tablist">
              <button className={source === "live" ? "on" : ""} onClick={() => setSource("live")}>Live interface</button>
              <button className={source === "replay" ? "on" : ""} onClick={() => setSource("replay")}>Replay capture</button>
            </div>

            {source === "live" ? (
              <>
                <label className="stack" style={{ gap: 4 }}>
                  <span className="muted">Interface</span>
                  <select className="select" value={iface} onChange={(e) => setIface(e.target.value)}>
                    {ifaces.map((i) => (
                      <option key={i.name} value={i.name}>
                        {i.friendly_name}{i.addresses.length ? ` — ${i.addresses.join(", ")}` : ""}{i.is_up ? "" : " (down)"}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="stack" style={{ gap: 4 }}>
                  <span className="muted">BPF filter (optional)</span>
                  <input className="input mono" placeholder="e.g. tcp or arp" value={filter} onChange={(e) => setFilter(e.target.value)} />
                </label>
                <span className="muted" style={{ fontSize: 12 }}>
                  Needs Administrator + Npcap on Windows, or root / CAP_NET_RAW on Linux.
                </span>
              </>
            ) : files.length ? (
              <>
                <label className="stack" style={{ gap: 4 }}>
                  <span className="muted">Capture file</span>
                  <select className="select" value={file} onChange={(e) => setFile(e.target.value)}>
                    {files.map((f) => <option key={f.name} value={f.name}>{f.name}</option>)}
                  </select>
                </label>
                <div className="row">
                  <label className="row" style={{ gap: 6 }}>
                    <span className="muted">Speed</span>
                    <select className="select" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
                      {[0.5, 1, 2, 5, 10].map((s) => <option key={s} value={s}>{s}×</option>)}
                    </select>
                  </label>
                  <label className="row" style={{ gap: 6 }}>
                    <input type="checkbox" checked={loop} onChange={(e) => setLoop(e.target.checked)} /> Loop
                  </label>
                </div>
              </>
            ) : (
              <span className="muted">No .pcap files in the captures/ folder. Generate a sample with
                <code> python -m evaluation.sample_capture</code>.</span>
            )}

            {error && <div className="banner error" style={{ fontSize: 13 }}>{error}</div>}
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button className="btn" onClick={() => setOpen(false)}>Cancel</button>
              <button className="btn primary" onClick={start} disabled={busy || (source === "replay" && !file)}>
                <Icon.play /> Start
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
