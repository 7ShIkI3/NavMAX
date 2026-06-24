"""
Gestionnaire de workspaces — projets isolés pour les investigations.

Un workspace regroupe :
- Des cibles (targets)
- Des scans
- Des sessions proxy
- Des graphes OSINT
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.db.models import Workspace, Target
from navmax.core.logging import get_logger

logger = get_logger(__name__)


class WorkspaceManager:
    """CRUD + logique métier pour les workspaces."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, name: str, description: str = "") -> Workspace:
        """Crée un nouveau workspace."""
        ws = Workspace(
            id=str(uuid.uuid4()),
            name=name,
            description=description or None,
        )
        self._session.add(ws)
        await self._session.flush()
        logger.info("workspace_créé", id=ws.id, name=name)
        return ws

    async def get(self, workspace_id: str) -> Workspace | None:
        """Récupère un workspace par ID."""
        result = await self._session.execute(
            select(Workspace).where(Workspace.id == workspace_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Workspace]:
        """Liste tous les workspaces."""
        result = await self._session.execute(
            select(Workspace).order_by(Workspace.updated_at.desc())
        )
        return list(result.scalars().all())

    async def update(self, workspace_id: str, name: str | None = None, description: str | None = None) -> Workspace | None:
        """Met à jour un workspace."""
        ws = await self.get(workspace_id)
        if not ws:
            return None
        if name is not None:
            ws.name = name
        if description is not None:
            ws.description = description
        ws.updated_at = datetime.now(timezone.utc)
        await self._session.flush()
        return ws

    async def delete(self, workspace_id: str) -> bool:
        """Supprime un workspace et toutes ses cibles (cascade)."""
        ws = await self.get(workspace_id)
        if not ws:
            return False
        await self._session.delete(ws)
        await self._session.flush()
        logger.info("workspace_supprimé", id=workspace_id)
        return True

    async def get_stats(self, workspace_id: str) -> dict:
        """Retourne les statistiques d'un workspace."""
        ws = await self.get(workspace_id)
        if not ws:
            return {"error": "Workspace introuvable"}

        # Compter les cibles via requête (évite lazy loading + MissingGreenlet)
        target_result = await self._session.execute(
            select(func.count(Target.id)).where(Target.workspace_id == workspace_id)
        )
        target_count = target_result.scalar() or 0

        return {
            "id": ws.id,
            "name": ws.name,
            "description": ws.description,
            "target_count": target_count,
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
            "updated_at": ws.updated_at.isoformat() if ws.updated_at else None,
        }

    async def add_target(self, workspace_id: str, target_id: str) -> bool:
        """Associe une cible existante à un workspace."""
        ws = await self.get(workspace_id)
        if not ws:
            return False
        result = await self._session.execute(
            select(Target).where(Target.id == target_id)
        )
        target = result.scalar_one_or_none()
        if not target:
            return False
        target.workspace_id = workspace_id
        await self._session.flush()
        return True

    async def remove_target(self, workspace_id: str, target_id: str) -> bool:
        """Désassocie une cible d'un workspace."""
        result = await self._session.execute(
            select(Target).where(
                Target.id == target_id,
                Target.workspace_id == workspace_id,
            )
        )
        target = result.scalar_one_or_none()
        if not target:
            return False
        target.workspace_id = None
        await self._session.flush()
        return True

    async def list_targets(self, workspace_id: str) -> list[Target]:
        """Liste les cibles d'un workspace."""
        result = await self._session.execute(
            select(Target).where(Target.workspace_id == workspace_id)
        )
        return list(result.scalars().all())
