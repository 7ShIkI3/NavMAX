"""Routes API pour la gestion des workspaces."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.db.engine import get_session
from navmax.workspace import WorkspaceManager
from navmax.core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field("")


class WorkspaceUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None


class TargetAssign(BaseModel):
    target_id: str


@router.post("/")
async def create_workspace(req: WorkspaceCreate, session: AsyncSession = Depends(get_session)) -> dict:
    """Crée un nouveau workspace."""
    mgr = WorkspaceManager(session)
    ws = await mgr.create(req.name, req.description)
    logger.info("workspace_créé", id=ws.id, name=ws.name)
    return {"id": ws.id, "name": ws.name, "description": ws.description}


@router.get("/")
async def list_workspaces(session: AsyncSession = Depends(get_session)) -> dict:
    """Liste tous les workspaces."""
    mgr = WorkspaceManager(session)
    ws_list = await mgr.list_all()
    return {
        "count": len(ws_list),
        "workspaces": [
            {"id": w.id, "name": w.name, "description": w.description,
             "target_count": len(w.targets) if w.targets else 0,
             "created_at": w.created_at.isoformat() if w.created_at else None}
            for w in ws_list
        ]
    }


@router.get("/{workspace_id}")
async def get_workspace(workspace_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    """Détail d'un workspace avec ses statistiques."""
    mgr = WorkspaceManager(session)
    stats = await mgr.get_stats(workspace_id)
    if "error" in stats:
        raise HTTPException(404, stats["error"])
    return stats


@router.patch("/{workspace_id}")
async def update_workspace(workspace_id: str, req: WorkspaceUpdate, session: AsyncSession = Depends(get_session)) -> dict:
    """Met à jour un workspace."""
    mgr = WorkspaceManager(session)
    ws = await mgr.update(workspace_id, req.name, req.description)
    if not ws:
        raise HTTPException(404, "Workspace introuvable")
    logger.info("workspace_mis_à_jour", id=workspace_id)
    return {"id": ws.id, "name": ws.name, "description": ws.description}


@router.delete("/{workspace_id}")
async def delete_workspace(workspace_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    """Supprime un workspace."""
    mgr = WorkspaceManager(session)
    ok = await mgr.delete(workspace_id)
    if not ok:
        raise HTTPException(404, "Workspace introuvable")
    logger.info("workspace_supprimé", id=workspace_id)
    return {"deleted": True}


@router.post("/{workspace_id}/targets")
async def add_target_to_workspace(workspace_id: str, req: TargetAssign, session: AsyncSession = Depends(get_session)) -> dict:
    """Associe une cible à un workspace."""
    mgr = WorkspaceManager(session)
    ok = await mgr.add_target(workspace_id, req.target_id)
    if not ok:
        raise HTTPException(404, "Workspace ou cible introuvable")
    return {"associated": True}


@router.delete("/{workspace_id}/targets/{target_id}")
async def remove_target_from_workspace(workspace_id: str, target_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    """Désassocie une cible d'un workspace."""
    mgr = WorkspaceManager(session)
    ok = await mgr.remove_target(workspace_id, target_id)
    if not ok:
        raise HTTPException(404, "Association introuvable")
    return {"disassociated": True}


@router.get("/{workspace_id}/targets")
async def list_workspace_targets(workspace_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    """Liste les cibles d'un workspace."""
    mgr = WorkspaceManager(session)
    targets = await mgr.list_targets(workspace_id)
    return {
        "count": len(targets),
        "targets": [
            {"id": t.id, "name": t.name, "address": t.address, "kind": t.kind}
            for t in targets
        ]
    }
