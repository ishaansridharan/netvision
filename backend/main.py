"""
NetVision — FastAPI Application Entry Point (main.py)

Start with (from the project root):
    uvicorn backend.main:app --host 0.0.0.0 --port 8000

Live capture needs privileges: Administrator + Npcap on Windows; root or
CAP_NET_RAW on Linux.  Replaying a pcap file needs none.

Swagger UI: http://localhost:8000/docs
ReDoc:       http://localhost:8000/redoc
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import (
    alerts, detection, flows, health, interfaces, packets, reports, stats, topology,
)
from backend.api.state import anomaly_detector, capture_engine, db_writer
from backend.api.websocket import router as ws_router
from backend.config import settings
from backend.detection.models import Alert
from backend.storage.database import init_db, load_recent_alerts, prune

# ──────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netvision")

_PRUNE_INTERVAL_S = 3600
_SNAPSHOT_RETENTION_S = 7 * 24 * 3600


async def _prune_loop() -> None:
    while True:
        await asyncio.sleep(_PRUNE_INTERVAL_S)
        try:
            await asyncio.to_thread(
                prune, settings.max_packets_stored, _SNAPSHOT_RETENTION_S, time.time()
            )
        except Exception as exc:
            logger.warning("DB prune failed: %s", exc)


def _restore_alerts() -> None:
    try:
        rows = load_recent_alerts()
    except Exception as exc:
        logger.warning("Could not load alert history: %s", exc)
        return
    restored = []
    for row in rows:
        row = {k: v for k, v in row.items() if v is not None}
        restored.append(Alert(**row))
    anomaly_detector.load_history(restored)
    if restored:
        logger.info("Restored %d alerts from the database.", len(restored))


# ──────────────────────────────────────────────────────────────────────────
# Startup / shutdown lifecycle
# ──────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise all background services on startup, tear down on shutdown."""
    logger.info("=" * 60)
    logger.info("  NetVision %s  —  starting up", settings.app_version)
    logger.info("=" * 60)

    init_db()
    _restore_alerts()
    db_writer.start()
    capture_engine.start_worker()
    prune_task = asyncio.create_task(_prune_loop())

    logger.info("All services started (detection mode: %s). Ready to capture.",
                anomaly_detector.mode)
    logger.info("Swagger UI: http://localhost:8000/docs")

    yield  # Application runs here

    logger.info("Shutting down NetVision…")
    prune_task.cancel()
    with suppress(asyncio.CancelledError):
        await prune_task
    capture_engine.stop()
    capture_engine.stop_worker()
    db_writer.stop()
    logger.info("Shutdown complete.")


# ──────────────────────────────────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_title,
    version=settings.app_version,
    description=(
        "NetVision backend API — real-time network traffic monitoring, "
        "flow tracking, statistics, and explainable anomaly detection with "
        "static or adaptive thresholds."
    ),
    lifespan=lifespan,
)

# ── CORS (allow the frontend dev server on any port) ──────────────────── #
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Restrict to specific origin in production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include routers ───────────────────────────────────────────────────── #
for module in (health, interfaces, packets, flows, stats, alerts,
               detection, topology, reports):
    app.include_router(module.router)
app.include_router(ws_router)


# ── Static content ────────────────────────────────────────────────────── #
# Evaluation charts (shown in the Reports view) and, when built, the UI.
_ROOT = Path(__file__).resolve().parent.parent
_EVAL_DIR = _ROOT / "evaluation" / "results"
_EVAL_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/evaluation-results", StaticFiles(directory=_EVAL_DIR), name="evaluation-results")

_UI_DIR = _ROOT / "frontend" / "dist"
if _UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=_UI_DIR, html=True), name="ui")

    # Client-side routes (/ui/security, …) must fall back to index.html.
    @app.exception_handler(404)
    async def _spa_fallback(request: Request, exc):
        if request.url.path.startswith("/ui/"):
            return FileResponse(_UI_DIR / "index.html")
        return JSONResponse({"detail": getattr(exc, "detail", "Not Found")}, status_code=404)


@app.get("/", include_in_schema=False)
def root():
    if _UI_DIR.is_dir():
        return RedirectResponse("/ui/")
    return {
        "name": "NetVision API",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "status": "running",
        "ui": "not built — run `npm run build` in frontend/, or `npm run dev` for development",
    }
