"""
NetVision — FastAPI Application Entry Point (main.py)

Start with:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Must be run as Administrator on Windows for packet capture to work.

Swagger UI: http://localhost:8000/docs
ReDoc:       http://localhost:8000/redoc
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.storage.database import init_db
from backend.api.state import stats_engine, db_writer
from backend.api.routes import interfaces, packets, flows, stats, alerts, health
from backend.api.websocket import router as ws_router

# ──────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netvision")


# ──────────────────────────────────────────────────────────────────────────
# Startup / shutdown lifecycle
# ──────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise all background services on startup, tear down on shutdown."""
    logger.info("=" * 60)
    logger.info("  NetVision %s  —  starting up", settings.app_version)
    logger.info("=" * 60)

    # 1. Initialise the database
    init_db()

    # 2. Start the stats engine snapshot thread
    stats_engine.start()

    # 3. Start the async DB write queue
    db_writer.start()

    logger.info("All services started. Ready to capture.")
    logger.info("Swagger UI: http://localhost:8000/docs")

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down NetVision…")
    stats_engine.stop()
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
        "flow tracking, statistics, and anomaly detection."
    ),
    lifespan=lifespan,
)

# ── CORS (allow React dev server on any port) ─────────────────────────── #
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Restrict to specific origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include routers ───────────────────────────────────────────────────── #
app.include_router(health.router)
app.include_router(interfaces.router)
app.include_router(packets.router)
app.include_router(flows.router)
app.include_router(stats.router)
app.include_router(alerts.router)
app.include_router(ws_router)


# ── Root redirect ─────────────────────────────────────────────────────── #
@app.get("/", include_in_schema=False)
def root():
    return {
        "name": "NetVision API",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "status": "running",
    }
