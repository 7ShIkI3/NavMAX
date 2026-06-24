"""
Application FastAPI — point d'entrée de l'API NavMAX.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from navmax.core.config import config
from navmax.core.logging import setup_logging, get_logger
from navmax.db import create_all

from .routes import targets, scans, proxy, exploit, osint, workspaces, ai

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Démarrage / arrêt de l'API."""
    setup_logging()
    await create_all()
    logger.info("api_démarrée", host=config.api_host, port=config.api_port)
    yield
    # Nettoyer le proxy
    from navmax.api.routes.proxy import _proxy_server as _ps, _web_scanner as _ws, _fuzzer as _fz
    if _ps and _ps.running:
        await _ps.stop()

    logger.info("api_arrêtée")


app = FastAPI(
    title="NavMAX API",
    description="Plateforme de cybersécurité unifiée pour agents IA",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — ouvert pour les agents IA locaux
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(targets.router, prefix="/api/v1/targets", tags=["Targets"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(proxy.router, prefix="/api/v1/proxy", tags=["Proxy"])
app.include_router(exploit.router, prefix="/api/v1/exploit", tags=["Exploit"])
app.include_router(osint.router, prefix="/api/v1/osint", tags=["OSINT"])
app.include_router(workspaces.router, prefix="/api/v1/workspaces", tags=["Workspaces"])
app.include_router(ai.router, tags=["AI"])


@app.get("/api/v1/health")
async def health() -> dict:
    """Point de santé — utilisé par les agents pour vérifier que l'API est vivante."""
    return {"status": "ok", "version": "0.1.0"}
