"""Application FastAPI — point d'entrée de l'API NavMAX.

Protection : JWT (sauf /docs, /redoc, /health, /api/v1/auth/*),
RBAC (admin/operator/viewer), rate limiting (slowapi), CORS.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from navmax.api.auth import (
    auth_router,
    limiter,
    require_role,
)
from navmax.api.schemas_responses import HealthResponse
from navmax.core.config import config
from navmax.core.logging import get_logger, setup_logging
from navmax.db import create_all

from .routes import ad, ai, exploit, firewall, nuclei, osint, proxy, scans, targets, workspaces

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Démarrage / arrêt de l'API."""
    setup_logging()
    await create_all()
    logger.info(
        "navmax_démarrage",
        host=config.api_host,
        port=config.api_port,
        debug=getattr(config, "debug", False),
    )

    # ── Vérification startup : nuclei ───────────────────────────
    try:
        from navmax.scanner.nuclei_scanner import NucleiScanner

        nuclei_scanner = NucleiScanner()
        nuclei_ok = await nuclei_scanner.check_installed()
        if nuclei_ok:
            logger.info("nuclei_startup_ok", path=nuclei_scanner._binary)
            templates_ok = await nuclei_scanner.check_templates()
            if not templates_ok:
                logger.warning(
                    "nuclei_templates_manquants_startup",
                    message=(
                        "Templates nuclei non trouvés. "
                        "Exécutez 'nuclei -update-templates' ou "
                        "appelez POST /api/v1/nuclei/update-templates"
                    ),
                )
        else:
            logger.warning(
                "nuclei_non_installé_startup",
                message=(
                    "Le binaire nuclei n'est pas installé. "
                    "Le scanner de vulnérabilités sera indisponible. "
                    "Installez-le via : go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                ),
            )
    except Exception as exc:
        logger.exception("nuclei_startup_erreur", erreur=str(exc))
    # ── Fin vérification startup ────────────────────────────────
    yield
    # Nettoyer le proxy
    from navmax.api.routes.proxy import _proxy_server as _ps

    if _ps and _ps.running:
        await _ps.stop()

    # Nettoyer les pools HTTP
    from navmax.core.http_client import close_all
    await close_all()

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
# ATTENTION : En production, restreindre aux origines autorisées uniquement
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

# Nuclei (vulnérabilités → operator+)
app.include_router(
    nuclei.router,
    prefix="/api/v1/nuclei",
    tags=["Nuclei"],
    dependencies=operator_or_admin,
)


# ── Dashboard (static files) ─────────────────────────────────────
import os

static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/dashboard", StaticFiles(directory=static_dir, html=True), name="dashboard")
logger.info("dashboard_monté", path=static_dir)


# ── Health check (public) ───────────────────────────────────────
@app.get("/api/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Point de santé — utilisé par les agents pour vérifier que l'API est vivante."""
    return HealthResponse(status="ok", version="0.1.0")
