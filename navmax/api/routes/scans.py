"""
Routes API pour les scans réseau (Nmap-like) — support Celery async + SSE streaming.
"""

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.core.logging import get_logger
from navmax.db import Scan, Target, get_session
from navmax.scanner.engine import parse_ports
from navmax.tasks import celery_app

from ..schemas import (
    Pagination,
    ScanCreate,
    ScanCreateResponse,
    ScanListResponse,
    ScanResponse,
    TaskStatusResponse,
)

router = APIRouter()
logger = get_logger(__name__)


@router.post("/", response_model=ScanCreateResponse, status_code=201)
async def create_scan(body: ScanCreate, db: AsyncSession = Depends(get_session)) -> dict:
    """Lance un scan en arrière-plan via une tâche Celery.

    Crée l'enregistrement en base, puis soumet la tâche avec task_id = scan.id
    afin que le Celery worker puisse faire le lien entre les deux.
    """
    # Vérifier que la cible existe
    target = await db.get(Target, body.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Cible introuvable")

    # Ports par défaut si non spécifiés
    from navmax.core.config import config  # noqa: PLC0415

    ports = body.ports or config.scanner_default_ports

    scan = Scan(
        target_id=body.target_id,
        scan_type=body.scan_type,
        ports=ports,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Lancer la tâche Celery avec task_id = scan.id (lien direct entre les deux)
    celery_app.send_task(
        "navmax.tasks.scan_tasks.run_nmap_scan",
        args=[target.address, ports, body.scan_type],
        task_id=scan.id,
    )

    logger.info(
        "scan_celery_lancé",
        scan_id=scan.id,
        target=body.target_id,
        type=body.scan_type,
    )

    return ScanCreateResponse(
        task_id=scan.id,
        scan_id=scan.id,
        status="PENDING",
        message="Scan lancé en arrière-plan",
    ).model_dump()


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    target_id: str | None = Query(None),
    status: str | None = Query(None),
    scan_type: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_session),
) -> dict:
    """Liste les scans avec pagination et filtres."""
    q = select(Scan)
    count_q = select(func.count(Scan.id))

    if target_id:
        q = q.where(Scan.target_id == target_id)
        count_q = count_q.where(Scan.target_id == target_id)
    if status:
        q = q.where(Scan.status == status)
        count_q = count_q.where(Scan.status == status)
    if scan_type:
        q = q.where(Scan.scan_type == scan_type)
        count_q = count_q.where(Scan.scan_type == scan_type)

    total = (await db.execute(count_q)).scalar() or 0
    rows = (await db.execute(
        q.order_by(Scan.created_at.desc()).offset(offset).limit(limit)
    )).scalars().all()

    return {
        "data": rows,
        "pagination": Pagination(total=total, offset=offset, limit=limit),
    }


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_session)) -> Scan:
    """Récupère un scan par ID (avec sa progression depuis la base)."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan


@router.get("/{scan_id}/status", response_model=TaskStatusResponse)
async def get_scan_status(scan_id: str) -> TaskStatusResponse:
    """Retourne le statut Celery d'une tâche de scan."""
    result = celery_app.AsyncResult(scan_id)
    meta = result.info if result.info else {}

    return TaskStatusResponse(
        task_id=scan_id,
        state=result.state,
        meta=meta if isinstance(meta, dict) else None,
        result=result.result if result.state in ("SUCCESS", "FAILURE") else None,
    )


@router.get("/{scan_id}/stream")
async def stream_scan_progress(scan_id: str):
    """SSE stream de la progression d'un scan Celery en temps réel."""
    result = celery_app.AsyncResult(scan_id)

    async def event_stream(task_id: str) -> str:
        last_state = None
        while True:
            res = celery_app.AsyncResult(task_id)
            state = res.state
            meta = res.info if res.info else {}

            if state != last_state or True:  # toujours envoyer la première trame
                data = json.dumps({"state": state, **meta})
                yield f"event: {state.lower()}\ndata: {data}\n\n"
                last_state = state

            if state in ("SUCCESS", "FAILURE", "REVOKED"):
                break

            await asyncio.sleep(1)  # intervalle de polling

    return StreamingResponse(
        event_stream(scan_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_session)) -> None:
    """Supprime un scan et sa tâche Celery associée."""
    # Révoquer la tâche Celery si elle existe encore
    from celery.exceptions import CeleryError  # noqa: PLC0415

    try:
        celery_app.control.revoke(scan_id, terminate=True, signal="SIGTERM")
    except CeleryError as exc:
        logger.debug("tâche_celery_déjà_terminée", task_id=scan_id, erreur=str(exc))
    except Exception as exc:  # noqa: BLE001 — fallback réseau/connexion Celery
        logger.debug("tâche_celery_erreur_révocation", task_id=scan_id, erreur=str(exc))

    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    await db.delete(scan)
    await db.commit()
    logger.info("scan_supprimé", scan_id=scan_id)
