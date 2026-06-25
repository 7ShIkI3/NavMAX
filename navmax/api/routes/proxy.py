"""
Routes API pour le proxy web (Burp-like).
"""

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from navmax.proxy import (
    ProxyServer,
    Interceptor,
    InterceptedFlow,
    FlowAction,
    FlowStatus,
    Repeater,
    WebScanner,
    Fuzzer,
)
from navmax.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)

# Instances globales (partagées dans le processus API)
_proxy_server: ProxyServer | None = None
_interceptor = Interceptor()
_repeater = Repeater()
_web_scanner = WebScanner()
_fuzzer = Fuzzer()


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
@router.post("/start")
async def proxy_start(req: ProxyStartRequest) -> dict:
    """Démarre le serveur proxy MITM."""
    global _proxy_server
    if _proxy_server and _proxy_server.running:
        return {"status": "already_running", "host": _proxy_server.host, "port": _proxy_server.port}

    _proxy_server = ProxyServer(
        host=req.host,
        port=req.port,
        interceptor=_interceptor,
    )
    asyncio.create_task(_proxy_server.start())
    logger.info("proxy_démarré", host=req.host, port=req.port)
    return {"status": "started", "host": req.host, "port": req.port}


@router.post("/stop")
async def proxy_stop() -> dict:
    """Arrête le serveur proxy."""
    global _proxy_server
    if _proxy_server:
        await _proxy_server.stop()
        _proxy_server = None
        logger.info("proxy_arrêté")
        return {"status": "stopped"}
    return {"status": "not_running"}


@router.get("/status")
async def proxy_status() -> dict:
    """État du proxy."""
    if not _proxy_server:
        return {"running": False, "flow_count": 0, "intercept_enabled": _interceptor.intercept_enabled}
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
@router.post("/intercept/toggle")
async def intercept_toggle() -> dict:
    """Active/désactive l'interception."""
    _interceptor.intercept_enabled = not _interceptor.intercept_enabled
    return {"intercept_enabled": _interceptor.intercept_enabled}


@router.get("/flows")
async def list_flows(
    limit: int = Query(50, ge=1, le=200),
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
                "request_body": f.request_body.decode("utf-8", errors="replace")[:5000] if f.request_body else None,
                "response_status": f.response_status,
                "response_headers": f.response_headers,
                "response_body": f.response_body.decode("utf-8", errors="replace")[:5000] if f.response_body else None,
                "status": f.status.value,
            }
            for f in flows
        ],
        "count": len(flows),
    }


@router.post("/flows/{flow_id}/decide")
async def decide_flow(flow_id: str, decision: FlowDecision) -> dict:
    """Décide du sort d'un flux intercepté."""
    action = FlowAction(decision.action)
    modified = None
    if decision.modified_flow:
        modified = InterceptedFlow(**decision.modified_flow)

    ok = _interceptor.decide(flow_id, action, modified)
    if not ok:
        raise HTTPException(404, "Flux introuvable")
    return {"status": "ok", "flow_id": flow_id, "action": action.value}


# ---------------------------------------------------------------------------
# Scanner web
# ---------------------------------------------------------------------------
@router.post("/scan")
async def scan_url(req: ScanRequest) -> dict:
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
@router.post("/fuzz")
async def fuzz_url(req: FuzzRequest) -> dict:
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
@router.post("/replay")
async def replay_request(req: ReplayRequest) -> dict:
    """Rejoue une requête HTTP."""
    result = await _repeater.send(
        method=req.method,
        url=req.url,
        headers=req.headers,
        body=req.body or b"",
    )

    return {
        "status": result.status,
        "headers": result.headers,
        "body": result.body[:10_000],
        "elapsed_ms": result.elapsed_ms,
        "error": result.error,
    }


@router.get("/replay/history")
async def replay_history(limit: int = Query(20, ge=1, le=100)) -> dict:
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
        ]
    }
