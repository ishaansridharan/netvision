import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the dashboard runs on :5173 and every API path is proxied to
// the FastAPI backend on :8000.  A production build is served by FastAPI
// itself under /ui, so the same absolute paths work without a proxy.
const backend = process.env.NETVISION_BACKEND ?? "http://localhost:8000";
const apiPaths = [
  "/health", "/interfaces", "/capture", "/packets", "/flows", "/stats",
  "/alerts", "/detection", "/topology", "/hosts", "/reports", "/metrics",
  "/evaluation-results",
];

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: { charts: ["recharts"], vendor: ["react", "react-dom", "react-router-dom", "d3-force"] },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      ...Object.fromEntries(apiPaths.map((p) => [p, { target: backend, changeOrigin: true }])),
      "/ws": { target: backend.replace(/^http/, "ws"), ws: true },
    },
  },
});
