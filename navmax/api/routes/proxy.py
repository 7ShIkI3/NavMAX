"""Routes API pour le proxy web (Burp-like)."""

import asyncio
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from navmax.api.schemas_responses import (
    FlowDecisionResponse,
    FlowListResponse,
    FuzzResponse,
    InterceptToggleResponse,
    ProxyStartResponse,
    ProxyStatusResponse,
    ProxyStopResponse,
    ReplayHistoryResponse,
    ReplayResponse,
    ScanURLResponse,
)
from navmax.core.logging import get_logger
from navmax.proxy import (
    FlowAction,
    Fuzzer,
    InterceptedFlow,
    Interceptor,
    ProxyServer,
    Repeater,
    WebScanner,
)

router = APIRouter()
logger = get_logger(__name__)

# Instances globales (partagées dans le processus API)
_proxy_server: ProxyServer | None = None
_interceptor = Interceptor()
_repeater = Repeater()
_web_scanner = WebScanner()
_fuzzer = Fuzzer()


def _on_proxy_task_error(task: asyncio.Task) -> None:
    """Callback de fin de tâche proxy — log les erreurs."""
    exc = task.exception() if not task.cancelled() else None
    if exc:
        logger.error("proxy_start_error", error=repr(exc))


# ---------------------------------------------------------------------------
# Schémas
# ---------------------------------------------------------------------------
class ProxyStartRequest(BaseModel):
    host: str = Field("127.0.0.1")
    port: int = Field(8080)


class FlowDecision(BaseModel):
    action: str = Field(..., pattern="^(forward|drop|modify)$")
    modified_flow: dict[str, Any] | None = None


class ScanRequest(BaseModel):
    url: str
    method: str = "GET"
    params: dict[str, str] | None = None
    body: str | None = None


class FuzzRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    body: str | None = None
    categories: list[str] | None = None
    concurrency: int = 10


class ReplayRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] | None = None
    body: str | None = None


# ---------------------------------------------------------------------------
# Proxy lifecycle
# ---------------------------------------------------------------------------
@router.post(
    "/start",
    response_model=ProxyStartResponse,
    summary="Démarre le proxy MITM",
    description="Lance un serveur proxy MITM pour intercepter et analyser le trafic HTTP/HTTPS.",
    responses={200: {"description": "Proxy démarré ou déjà en cours"}},
)
async def proxy_start(req: ProxyStartRequest) -> ProxyStartResponse:
    """Démarre le serveur proxy MITM."""
    global _proxy_server
    if _proxy_server and _proxy_server.running:
        return ProxyStartResponse(status="already_running", host=_proxy_server.host, port=_proxy_server.port)

    _proxy_server = ProxyServer(
        host=req.host,
        port=req.port,
        interceptor=_interceptor,
    )
    task = asyncio.create_task(_proxy_server.start())
    task.add_done_callback(_on_proxy_task_error)
    logger.info("proxy_démarré", host=req.host, port=req.port)
    return ProxyStartResponse(status="started", host=req.host, port=req.port)


@router.post(
    "/stop",
    response_model=ProxyStopResponse,
    summary="Arrête le proxy",
    description="Arrête le serveur proxy MITM et libère le port.",
    responses={200: {"description": "Proxy arrêté ou non démarré"}},
)
async def proxy_stop() -> ProxyStopResponse:
    """Arrête le serveur proxy."""
    global _proxy_server
    if _proxy_server:
        await _proxy_server.stop()
        _proxy_server = None
        logger.info("proxy_arrêté")
        return ProxyStopResponse(status="stopped")
    return ProxyStopResponse(status="not_running")


@router.get(
    "/status",
    response_model=ProxyStatusResponse,
    summary="État du proxy",
    description="Retourne l'état actuel du proxy : running, ports, nombre de flux, état de l'interception.",
    responses={200: {"description": "État du proxy"}},
)
async def proxy_status() -> ProxyStatusResponse:
    """État du proxy."""
    if not _proxy_server:
        return {
            "running": False,
            "flow_count": 0,
            "intercept_enabled": _interceptor.intercept_enabled,
        }
    return {
        "running": _proxy_server.running,
        "host": _proxy_server.host,
        "port": _proxy_server.port,
        "flow_count": _proxy_server.flow_count,
        "intercept_enabled": _interceptor.intercept_enabled,
        "pending_count": _interceptor.pending_count,
    }


# ---------------------------------------------------------------------------
# Interception
# ---------------------------------------------------------------------------
@router.post(
    "/intercept/toggle",
    response_model=InterceptToggleResponse,
    summary="Active/désactive l'interception",
    description="Bascule l'état de l'interception des flux HTTP au niveau du proxy.",
    responses={200: {"description": "Nouvel état de l'interception"}},
)
async def intercept_toggle() -> InterceptToggleResponse:
    """Active/désactive l'interception."""
    _interceptor.intercept_enabled = not _interceptor.intercept_enabled
    return InterceptToggleResponse(intercept_enabled=_interceptor.intercept_enabled)


@router.get(
    "/flows",
    response_model=FlowListResponse,
    summary="Liste les flux interceptés",
    description="Retourne les derniers flux HTTP interceptés par le proxy avec les détails des requêtes/réponses.",
    responses={200: {"description": "Liste des flux"}},
)
async def list_flows(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict:
    """Liste les flux interceptés."""
    if _proxy_server:
        flows = _proxy_server.recent_flows[-limit:]
    else:
        flows = _interceptor.all_flows[-limit:]

    return {
        "data": [
            {
                "id": f.id,
                "method": f.method,
                "host": f.host,
                "port": f.port,
                "path": f.path,
                "request_headers": f.request_headers,
                "request_body": f.request_body.decode("utf-8", errors="replace")[:5000]
                if f.request_body
                else None,
                "response_status": f.response_status,
                "response_headers": f.response_headers,
                "response_body": f.response_body.decode("utf-8", errors="replace")[:5000]
                if f.response_body
                else None,
                "status": f.status.value,
            }
            for f in flows
        ],
        "count": len(flows),
    }


@router.post(
    "/flows/{flow_id}/decide",
    response_model=FlowDecisionResponse,
    summary="Décide du sort d'un flux intercepté",
    description="Permet de forwarder, dropper ou modifier un flux intercepté par le proxy.",
    responses={
        200: {"description": "Décision appliquée"},
        404: {"description": "Flux introuvable"},
    },
)
async def decide_flow(flow_id: str, decision: FlowDecision) -> FlowDecisionResponse:
    """Décide du sort d'un flux intercepté."""
    action = FlowAction(decision.action)
    modified = None
    if decision.modified_flow:
        modified = InterceptedFlow(**decision.modified_flow)

    ok = _interceptor.decide(flow_id, action, modified)
    if not ok:
        raise HTTPException(404, "Flux introuvable")
    return FlowDecisionResponse(status="ok", flow_id=flow_id, action=action.value)


# ---------------------------------------------------------------------------
# Scanner web
# ---------------------------------------------------------------------------
@router.post(
    "/scan",
    response_model=ScanURLResponse,
    summary="Scanne une URL pour les vulnérabilités web",
    description="Analyse une URL à la recherche de vulnérabilités web (XSS, SQLi, etc.) avec rapport détaillé.",
    responses={
        200: {"description": "Rapport de vulnérabilités"},
    },
)
async def scan_url(req: ScanRequest) -> ScanURLResponse:
    """Scanne une URL pour les vulnérabilités web."""
    logger.info("proxy_scan_web_lancé", url=req.url, method=req.method)
    vulns = await _web_scanner.scan_url(
        url=req.url,
        method=req.method,
        params=req.params,
        body=req.body,
    )

    logger.info("proxy_scan_web_terminé", url=req.url, vulns_count=len(vulns))
    return {
        "url": req.url,
        "vulnerability_count": len(vulns),
        "vulnerabilities": [
            {
                "name": v.name,
                "severity": v.severity,
                "parameter": v.parameter,
                "payload": v.payload,
                "evidence": v.evidence,
                "description": v.description,
                "remediation": v.remediation,
                "cwe": v.cwe,
            }
            for v in vulns
        ],
    }


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------
@router.post(
    "/fuzz",
    response_model=FuzzResponse,
    summary="Fuzze une URL avec des payloads d'attaque",
    description="Teste une URL avec des payloads d'attaque prédéfinis (XSS, injection, path traversal, etc.) et détecte les anomalies.",
    responses={
        200: {"description": "Rapport de fuzzing"},
    },
)
async def fuzz_url(req: FuzzRequest) -> FuzzResponse:
    """Fuzze une URL avec des payloads d'attaque."""
    logger.info("proxy_fuzz_lancé", url=req.url, method=req.method)
    report = await _fuzzer.fuzz_url(
        url=req.url,
        method=req.method,
        headers=req.headers,
        body=req.body,
    )

    logger.info("proxy_fuzz_terminé", url=req.url, anomalies=report.anomaly_count)
    return {
        "url": req.url,
        "total_tests": report.total_tests,
        "anomaly_count": report.anomaly_count,
        "duration_ms": report.duration_ms,
        "anomalies": [
            {
                "injection_point": a.injection_point,
                "parameter": a.parameter_name,
                "payload": a.payload,
                "category": a.payload_category,
                "anomaly": a.anomaly,
                "evidence": a.evidence,
            }
            for a in report.anomalies[:50]  # Max 50 anomalies
        ],
    }


# ---------------------------------------------------------------------------
# Repeater
# ---------------------------------------------------------------------------
@router.post(
    "/replay",
    response_model=ReplayResponse,
    summary="Rejoue une requête HTTP",
    description="Envoie une requête HTTP personnalisée (method, url, headers, body) et retourne la réponse complète.",
    responses={
        200: {"description": "Réponse du replay"},
    },
)
async def replay_request(req: ReplayRequest) -> ReplayResponse:
    """Rejoue une requête HTTP."""
    result = await _repeater.send(
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body or b"",
    )

    return ReplayResponse(
        status=result.status,
        headers=result.headers,
        body=result.body[:10_000],
        elapsed_ms=result.elapsed_ms,
        error=result.error,
    )


@router.get(
    "/replay/history",
    response_model=ReplayHistoryResponse,
    summary="Historique des replays",
    description="Retourne l'historique des requêtes replayées avec leur statut et temps de réponse.",
    responses={200: {"description": "Historique des replays"}},
)
async def replay_history(limit: Annotated[int, Query(ge=1, le=100)] = 20) -> ReplayHistoryResponse:
    """Historique des replays."""
    history = _repeater.history[-limit:]
    return {
        "data": [
            {
                "request": {
                    "method": h.request.method,
                    "url": h.request.url[:200],
                },
                "response": {
                    "status": h.response.status,
                    "elapsed_ms": h.response.elapsed_ms,
                    "error": h.response.error,
                },
                "timestamp": h.timestamp,
            }
            for h in history
        ],
    }
