"""Routes API pour le module OSINT (Maltego-like)."""

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from navmax.core.logging import get_logger
from navmax.osint import (
    DnsCollector,
    OsintOrchestrator,
    SslCollector,
    WebCollector,
    WhoisCollector,
)

router = APIRouter()
logger = get_logger(__name__)


class InvestigateRequest(BaseModel):
    target: str = Field(..., examples=["example.com", "1.1.1.1"])
    target_type: str = Field("domain", pattern="^(domain|ip)$")
    max_depth: int = Field(2, ge=1, le=3)


# ---------------------------------------------------------------------------
# Collecteurs individuels
# ---------------------------------------------------------------------------
@router.get("/dns/{domain}")
async def dns_lookup(
    domain: str,
    types: Annotated[str | None, Query(description="A,AAAA,MX,NS,TXT,CNAME,SOA (séparés par virgule)")] = None,
) -> dict:
    """Résolution DNS d'un domaine."""
    record_types = types.split(",") if types else None
    records = await DnsCollector.lookup(domain, record_types)
    return {
        "domain": domain,
        "count": len(records),
        "records": [
            {"type": r.type, "name": r.name, "value": r.value, "ttl": r.ttl} for r in records
        ],
    }


@router.get("/whois/{domain}")
async def whois_lookup(domain: str) -> dict:
    """WHOIS d'un domaine."""
    info = await WhoisCollector.lookup(domain)
    if info is None:
        return {"domain": domain, "error": "WHOIS inaccessible"}
    return {
        "domain": info.domain,
        "registrar": info.registrar,
        "creation_date": info.creation_date,
        "expiration_date": info.expiration_date,
        "updated_date": info.updated_date,
        "name_servers": info.name_servers,
        "registrant_name": info.registrant_name,
        "registrant_org": info.registrant_org,
        "registrant_email": info.registrant_email,
        "registrant_country": info.registrant_country,
    }


@router.get("/ssl/{host}")
async def ssl_lookup(host: str, port: Annotated[int, Query()] = 443) -> dict:
    """Certificat SSL d'un hôte."""
    info = await SslCollector.get_cert(host, port)
    if info is None:
        return {"host": host, "error": "Certificat inaccessible"}
    return {
        "host": info.host,
        "port": info.port,
        "subject": info.subject,
        "issuer": info.issuer,
        "serial_number": info.serial_number,
        "not_before": info.not_before,
        "not_after": info.not_after,
        "san": info.san,
        "fingerprint_sha256": info.fingerprint_sha256,
        "is_valid": info.is_valid,
        "days_remaining": info.days_remaining,
    }


@router.get("/web/{url:path}")
async def web_analyze(url: str) -> dict:
    """Analyse d'une page web."""
    # FastAPI décode l'URL → reconstruire
    from urllib.parse import unquote

    url = unquote(str(url))

    collector = WebCollector()
    info = await collector.analyze(url)
    await collector.close()

    if info is None:
        return {"url": url, "error": "Analyse échouée"}

    return {
        "url": info.url,
        "status_code": info.status_code,
        "title": info.title,
        "server": info.server,
        "technologies": info.technologies,
        "emails_found": info.emails_found,
        "links_external": info.links_external[:20],
        "social_links": info.social_links,
    }


# ---------------------------------------------------------------------------
# Investigation complète
# ---------------------------------------------------------------------------
@router.post("/investigate")
async def investigate(req: InvestigateRequest) -> dict:
    """Investigation OSINT complète (orchestrateur)."""
    logger.info(
        "osint_investigation_lancée", target=req.target, type=req.target_type, depth=req.max_depth,
    )
    orch = OsintOrchestrator(max_depth=req.max_depth)
    result = await orch.investigate(req.target, req.target_type)

    logger.info(
        "osint_investigation_terminée", target=req.target, nodes=result.get("node_count", 0),
    )
    graph_data = orch.export("cytoscape")
    return {
        "target": result["target"],
        "type": result["type"],
        "nodes": result["node_count"],
        "edges": result["edge_count"],
        "log": result["log"],
        "graph": graph_data,
    }


# ---------------------------------------------------------------------------
# Transforms disponibles
# ---------------------------------------------------------------------------
@router.get("/transforms")
async def list_transforms() -> dict:
    """Liste les transforms OSINT disponibles."""
    from navmax.osint.graph import ALL_TRANSFORMS

    return {
        "transforms": [
            {
                "name": t.name,
                "input_type": t.input_type.value,
                "description": t.description,
            }
            for t in ALL_TRANSFORMS.values()
        ],
    }
