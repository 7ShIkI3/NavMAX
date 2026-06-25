"""
Application FastAPI — point d'entrée de l'API NavMAX.

Protection : JWT (sauf /docs, /redoc, /health, /api/v1/auth/*),
RBAC (admin/operator/viewer), rate limiting (slowapi), CORS.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from navmax.core.config import config
from navmax.core.logging import setup_logging, get_logger
from navmax.db import create_all
from navmax.api.auth import (
    auth_router,
    limiter,
    get_current_user,
    require_role,
)

from .routes import targets, scans, proxy, exploit, osint, workspaces, ai, ad, firewall

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

# ── CORS ────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate Limiting (slowapi) ─────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


# ── Routes publiques (pas d'auth) ───────────────────────────────
# Auth (login, register, me avec token)
app.include_router(auth_router)


# ── Helper : protection RBAC ────────────────────────────────────
admin_only = [Depends(require_role("admin"))]
operator_or_admin = [Depends(require_role("operator"))]
viewer_or_higher = [Depends(require_role("viewer"))]


# Routes protégées ────────────────────────────────────────────
#
# Targets (lecture + écriture → viewer+)
app.include_router(
    targets.router,
    prefix="/api/v1/targets",
    tags=["Targets"],
    dependencies=viewer_or_higher,
)

# Scans (lecture + écriture → viewer+)
app.include_router(
    scans.router,
    prefix="/api/v1/scans",
    tags=["Scans"],
    dependencies=viewer_or_higher,
)

# Proxy (opérations sensibles → admin)
app.include_router(
    proxy.router,
    prefix="/api/v1/proxy",
    tags=["Proxy"],
    dependencies=admin_only,
)

# Exploit (extrêmement sensible → admin uniquement)
app.include_router(
    exploit.router,
    prefix="/api/v1/exploit",
    tags=["Exploit"],
    dependencies=admin_only,
)

# OSINT (lecture → viewer+)
app.include_router(
    osint.router,
    prefix="/api/v1/osint",
    tags=["OSINT"],
    dependencies=viewer_or_higher,
)

# Workspaces (lecture + écriture → viewer+)
app.include_router(
    workspaces.router,
    prefix="/api/v1/workspaces",
    tags=["Workspaces"],
    dependencies=viewer_or_higher,
)

# AI (peut être ouvert à operator+)
app.include_router(
    ai.router,
    tags=["AI"],
    dependencies=operator_or_admin,
)

# Active Directory (extrêmement sensible → admin)
app.include_router(
    ad.router,
    tags=["Active Directory"],
    dependencies=admin_only,
)

# Firewall (sensible → admin)
app.include_router(
    firewall.router,
    tags=["Firewall"],
    dependencies=admin_only,
)


# ── Health check (public) ───────────────────────────────────────
@app.get("/api/v1/health")
async def health() -> dict:
    """Point de santé — utilisé par les agents pour vérifier que l'API est vivante."""
    return {"status": "ok", "version": "0.1.0"}
