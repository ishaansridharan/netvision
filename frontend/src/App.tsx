import { useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { CaptureControl } from "./components/CaptureControl";
import { Icon } from "./components/ui";
import { useLive } from "./live";
import { Dashboard } from "./views/Dashboard";
import { NetworkMap } from "./views/NetworkMap";
import { Packets } from "./views/Packets";
import { Reports } from "./views/Reports";
import { Security } from "./views/Security";

const VIEWS = [
  { path: "/dashboard", label: "Dashboard", icon: Icon.dashboard, question: "What's happening on my network right now?" },
  { path: "/packets", label: "Live Packets", icon: Icon.packets, question: "What packets are actually moving?" },
  { path: "/map", label: "Network Map", icon: Icon.map, question: "Who is communicating with whom?" },
  { path: "/security", label: "Security", icon: Icon.shield, question: "Is anything suspicious happening?" },
  { path: "/reports", label: "Reports", icon: Icon.report, question: "Why was my network slow?" },
];

function ThemeToggle() {
  const [theme, setTheme] = useState<string | undefined>(document.documentElement.dataset.theme);
  const dark = theme ? theme === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  const toggle = () => {
    const next = dark ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("nv-theme", next); } catch { /* ignore */ }
    setTheme(next);
  };
  return (
    <button className="btn" onClick={toggle} aria-label={`Switch to ${dark ? "light" : "dark"} theme`}>
      {dark ? <Icon.sun /> : <Icon.moon />}
    </button>
  );
}

export function App() {
  const { unseenAlerts, mode, pipeline } = useLive();
  const loc = useLocation();
  const view = VIEWS.find((v) => loc.pathname.startsWith(v.path)) ?? VIEWS[0];

  return (
    <div className="app">
      <nav className="sidebar" aria-label="Views">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
            <circle cx="16" cy="16" r="14" fill="var(--series-1)" />
            <path d="M6 18l5-6 5 8 5-10 5 8" stroke="#fff" strokeWidth="2.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          NetVision
        </div>
        {VIEWS.map((v) => (
          <NavLink key={v.path} to={v.path} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <v.icon />
            {v.label}
            {v.path === "/security" && unseenAlerts > 0 && <span className="count num">{unseenAlerts} new</span>}
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <span>Detection: <b className="ink-2">{mode === "adaptive" ? "Adaptive" : "Static"}</b></span>
          {pipeline.processed_pps != null && (
            <span className="num">{Math.round(pipeline.processed_pps).toLocaleString()} pkt/s analysed</span>
          )}
        </div>
      </nav>

      <div className="main">
        <header className="topbar">
          <h1>{view.label} <span className="muted" style={{ fontWeight: 400, fontSize: 13, marginLeft: 8 }}>{view.question}</span></h1>
          <CaptureControl />
          <ThemeToggle />
        </header>
        <main className="content">
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/packets" element={<Packets />} />
            <Route path="/map" element={<NetworkMap />} />
            <Route path="/security" element={<Security />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
