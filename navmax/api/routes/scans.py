"""
Routes API pour les scans réseau (Nmap-like).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.db import Scan, Target, get_session
from navmax.core.logging import get_logger

from ..schemas import (
    Pagination,
    ScanCreate,
    ScanListResponse,
    ScanResponse,
)

router = APIRouter()
logger = get_logger(__name__)


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(body: ScanCreate, db: AsyncSession = Depends(get_session)) -> Scan:
    """Lance un nouveau scan sur une cible."""
    # Vérifier que la cible existe
    target = await db.get(Target, body.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Cible introuvable")

    # Ports par défaut si non spécifiés
    from navmax.core.config import config

    ports = body.ports or config.scanner_default_ports

    scan = Scan(
        target_id=body.target_id,
        scan_type=body.scan_type,
        ports=ports,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Lancer le scan en arrière-plan (via le hook du scanner)
    from navmax.scanner import run_scan_background  # noqa: PLC0415

    await run_scan_background(scan.id)

    logger.info("scan_créé", id=scan.id, target=body.target_id, type=body.scan_type)
    return scan


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
    rows = (await db.execute(q.order_by(Scan.created_at.desc()).offset(offset).limit(limit))).scalars().all()

    return {
        "data": rows,
        "pagination": Pagination(total=total, offset=offset, limit=limit),
    }


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_session)) -> Scan:
    """Récupère un scan par ID (avec sa progression)."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_session)) -> None:
    """Supprime un scan."""
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    await db.delete(scan)
    await db.commit()
