"""Routes API pour la gestion des workspaces."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.api.schemas_responses import (
    TargetAssignResponse,
    TargetRemoveResponse,
    WorkspaceCreateResponse,
    WorkspaceDeleteResponse,
    WorkspaceDetailResponse,
    WorkspaceListResponse,
    WorkspaceTargetListResponse,
    WorkspaceUpdateResponse,
)
from navmax.core.logging import get_logger
from navmax.db.engine import get_session
from navmax.workspace import WorkspaceManager

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


@router.post(
    "/",
    response_model=WorkspaceCreateResponse,
    status_code=201,
    summary="Crée un nouveau workspace",
    description="Crée un espace de travail pour organiser les cibles et les scans.",
    responses={201: {"description": "Workspace créé"}},
)
async def create_workspace(
    req: WorkspaceCreate, session: Annotated[AsyncSession, Depends(get_session)],
) -> WorkspaceCreateResponse:
    """Crée un nouveau workspace."""
    mgr = WorkspaceManager(session)
    ws = await mgr.create(req.name, req.description)
    logger.info("workspace_créé", id=ws.id, name=ws.name)
    return WorkspaceCreateResponse(id=ws.id, name=ws.name, description=ws.description)


@router.get(
    "/",
    response_model=WorkspaceListResponse,
    summary="Liste tous les workspaces",
    description="Retourne la liste complète des workspaces avec leur nombre de cibles.",
    responses={200: {"description": "Liste des workspaces"}},
)
async def list_workspaces(session: Annotated[AsyncSession, Depends(get_session)]) -> WorkspaceListResponse:
    """Liste tous les workspaces."""
    mgr = WorkspaceManager(session)
    ws_list = await mgr.list_all()
    return {
        "count": len(ws_list),
        "workspaces": [
            {
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "target_count": len(w.targets) if w.targets else 0,
                "created_at": w.created_at.isoformat() if w.created_at else None,
            }
            for w in ws_list
        ],
    }


@router.get(
    "/{workspace_id}",
    response_model=WorkspaceDetailResponse,
    summary="Détail d'un workspace",
    description="Retourne les informations détaillées et les statistiques d'un workspace.",
    responses={
        200: {"description": "Détail du workspace"},
        404: {"description": "Workspace introuvable"},
    },
)
async def get_workspace(workspace_id: str, session: Annotated[AsyncSession, Depends(get_session)]) -> WorkspaceDetailResponse:
    """Détail d'un workspace avec ses statistiques."""
    mgr = WorkspaceManager(session)
    stats = await mgr.get_stats(workspace_id)
    if "error" in stats:
        raise HTTPException(404, stats["error"])
    return WorkspaceDetailResponse(**stats)


@router.patch(
    "/{workspace_id}",
    response_model=WorkspaceUpdateResponse,
    summary="Met à jour un workspace",
    description="Modifie le nom et/ou la description d'un workspace existant.",
    responses={
        200: {"description": "Workspace mis à jour"},
        404: {"description": "Workspace introuvable"},
    },
)
async def update_workspace(
    workspace_id: str, req: WorkspaceUpdate, session: Annotated[AsyncSession, Depends(get_session)],
) -> WorkspaceUpdateResponse:
    """Met à jour un workspace."""
    mgr = WorkspaceManager(session)
    ws = await mgr.update(workspace_id, req.name, req.description)
    if not ws:
        raise HTTPException(404, "Workspace introuvable")
    logger.info("workspace_mis_à_jour", id=workspace_id)
    return WorkspaceUpdateResponse(id=ws.id, name=ws.name, description=ws.description)


@router.delete(
    "/{workspace_id}",
    response_model=WorkspaceDeleteResponse,
    summary="Supprime un workspace",
    description="Supprime un workspace et ses associations (les cibles ne sont pas supprimées).",
    responses={
        200: {"description": "Workspace supprimé"},
        404: {"description": "Workspace introuvable"},
    },
)
async def delete_workspace(workspace_id: str, session: Annotated[AsyncSession, Depends(get_session)]) -> WorkspaceDeleteResponse:
    """Supprime un workspace."""
    mgr = WorkspaceManager(session)
    ok = await mgr.delete(workspace_id)
    if not ok:
        raise HTTPException(404, "Workspace introuvable")
    logger.info("workspace_supprimé", id=workspace_id)
    return WorkspaceDeleteResponse(deleted=True)


@router.post(
    "/{workspace_id}/targets",
    response_model=TargetAssignResponse,
    status_code=201,
    summary="Associe une cible à un workspace",
    description="Ajoute une cible existante dans un workspace pour organiser les scans.",
    responses={
        201: {"description": "Cible associée"},
        404: {"description": "Workspace ou cible introuvable"},
    },
)
async def add_target_to_workspace(
    workspace_id: str, req: TargetAssign, session: Annotated[AsyncSession, Depends(get_session)],
) -> TargetAssignResponse:
    """Associe une cible à un workspace."""
    mgr = WorkspaceManager(session)
    ok = await mgr.add_target(workspace_id, req.target_id)
    if not ok:
        raise HTTPException(404, "Workspace ou cible introuvable")
    return TargetAssignResponse(associated=True)


@router.delete(
    "/{workspace_id}/targets/{target_id}",
    response_model=TargetRemoveResponse,
    summary="Désassocie une cible d'un workspace",
    description="Retire l'association d'une cible d'un workspace sans supprimer la cible.",
    responses={
        200: {"description": "Cible désassociée"},
        404: {"description": "Association introuvable"},
    },
)
async def remove_target_from_workspace(
    workspace_id: str, target_id: str, session: Annotated[AsyncSession, Depends(get_session)],
) -> TargetRemoveResponse:
    """Désassocie une cible d'un workspace."""
    mgr = WorkspaceManager(session)
    ok = await mgr.remove_target(workspace_id, target_id)
    if not ok:
        raise HTTPException(404, "Association introuvable")
    return TargetRemoveResponse(disassociated=True)


@router.get(
    "/{workspace_id}/targets",
    response_model=WorkspaceTargetListResponse,
    summary="Liste les cibles d'un workspace",
    description="Retourne la liste des cibles associées à un workspace.",
    responses={
        200: {"description": "Liste des cibles du workspace"},
        404: {"description": "Workspace introuvable"},
    },
)
async def list_workspace_targets(
    workspace_id: str, session: Annotated[AsyncSession, Depends(get_session)],
) -> WorkspaceTargetListResponse:
    """Liste les cibles d'un workspace."""
    mgr = WorkspaceManager(session)
    targets = await mgr.list_targets(workspace_id)
    return {
        "count": len(targets),
        "targets": [
            {"id": t.id, "name": t.name, "address": t.address, "kind": t.kind} for t in targets
        ],
    }
