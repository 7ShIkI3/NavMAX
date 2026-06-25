"""
Routes API pour les cibles (Targets).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.db import Target, get_session
from navmax.core.logging import get_logger

from ..schemas import (
    Pagination,
    TargetCreate,
    TargetListResponse,
    TargetResponse,
    TargetUpdate,
)

router = APIRouter()
logger = get_logger(__name__)


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(body: TargetCreate, db: AsyncSession = Depends(get_session)) -> Target:
    """Crée une nouvelle cible."""
    target = Target(**body.model_dump())
    db.add(target)
    await db.commit()
    await db.refresh(target)
    logger.info("cible_créée", id=target.id, address=target.address)
    return target


@router.get("/", response_model=TargetListResponse)
async def list_targets(
    kind: str | None = Query(None, description="Filtrer : host, subnet, domain"),
    alive: bool | None = Query(None, description="Filtrer par statut vivant"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_session),
) -> dict:
    """Liste les cibles avec pagination et filtres optionnels."""
    q = select(Target)
    count_q = select(func.count(Target.id))

    if kind:
        q = q.where(Target.kind == kind)
        count_q = count_q.where(Target.kind == kind)
    if alive is not None:
        q = q.where(Target.alive == alive)
        count_q = count_q.where(Target.alive == alive)

    total = (await db.execute(count_q)).scalar() or 0
    rows = (await db.execute(q.order_by(Target.created_at.desc()).offset(offset).limit(limit))).scalars().all()

    return {
        "data": rows,
        "pagination": Pagination(total=total, offset=offset, limit=limit),
    }


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_session)) -> Target:
    """Récupère une cible par ID."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Cible introuvable")
    return target


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(target_id: str, body: TargetUpdate, db: AsyncSession = Depends(get_session)) -> Target:
    """Met à jour une cible."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Cible introuvable")

    for key, val in body.model_dump(exclude_unset=True).items():
        setattr(target, key, val)
    await db.commit()
    await db.refresh(target)
    logger.info("cible_mise_à_jour", id=target_id)
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_session)) -> None:
    """Supprime une cible et ses données associées."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Cible introuvable")
    await db.delete(target)
    await db.commit()
    logger.info("cible_supprimée", id=target_id)
