"""
AuditLogger — traçabilité complète de toutes les actions NavMAX.

Chaque action (scan, exploit, collecte OSINT, appel IA, exécution de mission)
est horodatée, journalisée en DB, et liée à une mission (workspace).

Usage:
    audit = AuditLogger(session)
    async with audit.track("scan", "scanner.tcp", mission_id=ws.id, target="10.0.0.1") as ctx:
        result = await scanner.scan("10.0.0.1", ports=[22, 80, 443])
        ctx.result_summary = {"open_ports": 3}
"""

import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional, AsyncIterator
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class AuditContext:
    """Contexte d'une action en cours d'audit.

    L'utilisateur peut enrichir le contexte avant la fin (ex: result_summary).
    La sauvegarde en DB est automatique à la sortie du context manager.
    """
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: Optional[str] = None
    phase_id: Optional[str] = None
    action: str = ""
    module: str = ""
    target: Optional[str] = None
    parameters: Optional[dict] = None
    result_summary: Optional[dict] = None
    _start_time: float = field(default_factory=time.monotonic)


class AuditLogger:
    """Logger d'audit asynchrone avec context manager.

    Garantit que chaque action est tracée, même en cas d'erreur.
    """

    def __init__(self, session):
        """
        Args:
            session: SQLAlchemy AsyncSession
        """
        self.session = session

    @asynccontextmanager
    async def track(self, action: str, module: str, *,
                    mission_id: Optional[str] = None,
                    phase_id: Optional[str] = None,
                    target: Optional[str] = None,
                    parameters: Optional[dict] = None) -> AsyncIterator[AuditContext]:
        """Context manager qui trace une action du début à la fin.

        Usage:
            async with audit.track("exploit", "exploit.ssh_bruteforce",
                                    mission_id=ws.id, target="10.0.0.1") as ctx:
                result = await exploit.run()
                ctx.result_summary = {"success": True, "sessions": 1}

        En cas d'exception, l'entrée est sauvegardée avec status="failed".
        """
        ctx = AuditContext(
            mission_id=mission_id,
            phase_id=phase_id,
            action=action,
            module=module,
            target=target,
            parameters=parameters,
        )
        logger.info("audit_started",
                     entry_id=ctx.entry_id, action=action, module=module,
                     target=target)

        try:
            yield ctx
            await self._save(ctx, status="completed")
            logger.info("audit_completed",
                         entry_id=ctx.entry_id,
                         duration_ms=int((time.monotonic() - ctx._start_time) * 1000))
        except Exception as e:
            await self._save(ctx, status="failed", error=str(e))
            logger.error("audit_failed",
                          entry_id=ctx.entry_id,
                          error=str(e),
                          duration_ms=int((time.monotonic() - ctx._start_time) * 1000))
            raise

    async def log(self, action: str, module: str, *,
                  mission_id: Optional[str] = None,
                  phase_id: Optional[str] = None,
                  target: Optional[str] = None,
                  parameters: Optional[dict] = None,
                  result_summary: Optional[dict] = None,
                  status: str = "completed") -> str:
        """Log une action ponctuelle (sans context manager).

        Returns:
            L'ID de l'entrée d'audit créée.
        """
        from navmax.db.models import AuditEntry

        entry = AuditEntry(
            workspace_id=mission_id,
            phase_id=phase_id,
            action=action,
            module=module,
            target=target,
            parameters=parameters,
            result_summary=result_summary,
            status=status,
        )
        self.session.add(entry)
        await self.session.commit()
        return entry.id

    async def _save(self, ctx: AuditContext, status: str,
                    error: Optional[str] = None) -> None:
        """Sauvegarde l'entrée d'audit en DB."""
        from navmax.db.models import AuditEntry

        entry = AuditEntry(
            id=ctx.entry_id,
            workspace_id=ctx.mission_id,
            phase_id=ctx.phase_id,
            action=ctx.action,
            module=ctx.module,
            target=ctx.target,
            parameters=ctx.parameters,
            result_summary=ctx.result_summary,
            status=status,
            duration_ms=int((time.monotonic() - ctx._start_time) * 1000),
            error=error,
        )
        self.session.add(entry)
        await self.session.commit()

    async def get_entries(self, mission_id: Optional[str] = None,
                          action: Optional[str] = None,
                          status: Optional[str] = None,
                          limit: int = 50) -> list[dict]:
        """Récupère les entrées d'audit avec filtres optionnels.

        Args:
            mission_id: Filtrer par workspace
            action: Filtrer par type d'action (scan, exploit, ...)
            status: Filtrer par statut (completed, failed, ...)
            limit: Nombre max d'entrées

        Returns:
            Liste de dicts avec les champs d'audit
        """
        from sqlalchemy import select
        from navmax.db.models import AuditEntry

        stmt = select(AuditEntry).order_by(AuditEntry.created_at.desc())

        if mission_id:
            stmt = stmt.where(AuditEntry.workspace_id == mission_id)
        if action:
            stmt = stmt.where(AuditEntry.action == action)
        if status:
            stmt = stmt.where(AuditEntry.status == status)

        stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        entries = result.scalars().all()

        return [
            {
                "id": e.id,
                "mission_id": e.workspace_id,
                "phase_id": e.phase_id,
                "action": e.action,
                "module": e.module,
                "target": e.target,
                "status": e.status,
                "duration_ms": e.duration_ms,
                "error": e.error,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
        ]
