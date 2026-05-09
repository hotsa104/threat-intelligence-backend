"""
FastAPI main application with lifespan management
Day 1: ES health check
Day 2+: SSH tunnel, scheduler, routes
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from db.ti_db import init_db
from routes.vulnerabilities import router as vuln_router
from routes.threats import router as threats_router
from services.ti_scheduler import start_scheduler, stop_scheduler

# === Logging Setup ===
logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# === Global State ===
es_local_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan events: startup and shutdown
    Day 1: ES health check
    Day 2: Add SSH tunnel + scheduler
    """
    # === STARTUP ===
    logger.info("🚀 Starting application...")

    # Initialize SQLite DB
    init_db()

    # Initialize ES client
    global es_local_client
    es_local_client = httpx.AsyncClient(timeout=30.0)
    logger.info(f"✅ ES client initialized (timeout: 30s)")

    # Test ES connectivity (optional — does not block startup)
    try:
        health = await es_local_client.get(f"{settings.local_es_url}/_cluster/health")
        health_data = health.json()
        logger.info(f"✅ Local ES health: {health_data['status']}")
    except Exception as e:
        logger.warning(f"⚠️ Could not reach ES (non-fatal): {e}")

    # Start incremental sync scheduler
    if settings.scheduler_enabled:
        start_scheduler()

    yield

    # === SHUTDOWN ===
    logger.info("🛑 Shutting down...")
    stop_scheduler()
    if es_local_client:
        await es_local_client.aclose()
    logger.info("✅ Cleanup complete")


# === FastAPI App ===
app = FastAPI(
    title="Threat Intelligence Dashboard API",
    description="Phase A MVP: CISA KEV + EPSS + NVD + T-pot",
    version="0.1.0",
    lifespan=lifespan,
)

# === CORS ===
# Allow Vercel frontend + localhost for development
cors_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
if settings.frontend_url:
    cors_origins.append(settings.frontend_url)
if settings.env == "development":
    cors_origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Routers ===
app.include_router(vuln_router)
app.include_router(threats_router)

# === Static Files ===
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")


# === Dashboard UI ===
@app.get("/", include_in_schema=False)
async def dashboard():
    """ダッシュボード HTML を返す"""
    index = Path(__file__).parent / "static" / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index)


# === Health Check Routes ===
@app.get("/health")
async def health_check():
    """API health check"""
    return {
        "status": "ok",
        "service": "threat-intel-dashboard-api",
        "version": "0.1.0",
    }


@app.get("/health/es")
async def es_health():
    """Check local ES health"""
    if not es_local_client:
        raise HTTPException(status_code=503, detail="ES client not initialized")

    try:
        response = await es_local_client.get(f"{settings.local_es_url}/_cluster/health")
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"ES unreachable: {str(e)}")


# === Placeholder Routes (for Phase A structure) ===
@app.get("/api/stats/summary")
async def stats_summary():
    """GET /api/stats/summary - Phase 7 implementation"""
    return {
        "critical_count": 0,
        "tpot_attacks_24h": 0,
        "kev_count": 0,
        "message": "Not implemented yet (Phase 7)",
    }


@app.get("/api/honeypot/stats")
async def honeypot_stats():
    """GET /api/honeypot/stats - Phase 6 implementation"""
    return {
        "top_ports": [],
        "total": 0,
        "message": "Not implemented yet (Phase 6)",
    }


@app.post("/api/refresh")
async def manual_refresh():
    """POST /api/refresh - Phase 8 implementation"""
    return {
        "status": "Not implemented yet (Phase 8)",
        "message": "Manual refresh trigger",
    }


if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting server on 0.0.0.0:{settings.fastapi_port}")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.fastapi_port,
        reload=settings.fastapi_reload,
    )
