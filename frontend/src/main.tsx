import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "./theme.css";
import { App } from "./App";
import { LiveProvider } from "./live";

try {
  const saved = localStorage.getItem("nv-theme");
  if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
} catch {
  /* storage unavailable — follow the OS setting */
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter basename="/ui">
      <LiveProvider>
        <App />
      </LiveProvider>
    </BrowserRouter>
  </StrictMode>,
);
