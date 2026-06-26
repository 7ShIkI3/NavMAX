"""Tests pour AuditLogger — traçabilité des actions."""

from typing import Never

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from navmax.core.audit import AuditLogger
from navmax.db.models import Base, Workspace


@pytest.fixture
async def session():
    """Session SQLite en mémoire pour les tests."""
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def workspace(session):
    ws = Workspace(name="Test Mission", description="Mission de test")
    session.add(ws)
    await session.commit()
    return ws


class TestAuditLogger:
    @pytest.mark.asyncio
    async def test_track_completed(self, session, workspace) -> None:
        audit = AuditLogger(session)

        async with audit.track(
            "scan", "scanner.tcp", mission_id=workspace.id, target="10.0.0.1",
        ) as ctx:
            ctx.result_summary = {"open_ports": 3}

        entries = await audit.get_entries(mission_id=workspace.id)
        assert len(entries) == 1
        assert entries[0]["action"] == "scan"
        assert entries[0]["status"] == "completed"
        assert entries[0]["target"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_track_failed(self, session, workspace) -> Never:
        audit = AuditLogger(session)

        with pytest.raises(ValueError):
            async with audit.track("exploit", "exploit.ssh_bruteforce", mission_id=workspace.id):
                msg = "Connection refused"
                raise ValueError(msg)

        entries = await audit.get_entries(mission_id=workspace.id)
        assert len(entries) == 1
        assert entries[0]["status"] == "failed"
        assert "Connection refused" in entries[0]["error"]

    @pytest.mark.asyncio
    async def test_log_simple(self, session, workspace) -> None:
        audit = AuditLogger(session)

        entry_id = await audit.log(
            "osint_collect",
            "osint.dns",
            mission_id=workspace.id,
            target="example.com",
            result_summary={"a_records": ["93.184.216.34"]},
        )

        assert entry_id is not None
        entries = await audit.get_entries(mission_id=workspace.id)
        assert len(entries) == 1
        assert entries[0]["action"] == "osint_collect"
        assert entries[0]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_multiple_entries(self, session, workspace) -> None:
        audit = AuditLogger(session)

        async with audit.track("scan", "scanner.tcp", mission_id=workspace.id):
            pass
        async with audit.track("exploit", "exploit.redis_unauth", mission_id=workspace.id):
            pass
        await audit.log("ia_generate", "ia.planner", mission_id=workspace.id)

        entries = await audit.get_entries(mission_id=workspace.id)
        assert len(entries) == 3

    @pytest.mark.asyncio
    async def test_filter_by_action(self, session, workspace) -> None:
        audit = AuditLogger(session)

        async with audit.track("scan", "scanner.tcp", mission_id=workspace.id):
            pass
        async with audit.track("exploit", "exploit.ssh", mission_id=workspace.id):
            pass

        scan_entries = await audit.get_entries(action="scan")
        assert len(scan_entries) == 1
        assert scan_entries[0]["action"] == "scan"

    @pytest.mark.asyncio
    async def test_filter_by_status(self, session, workspace) -> Never:
        audit = AuditLogger(session)

        async with audit.track("scan", "scanner.tcp", mission_id=workspace.id):
            pass
        with pytest.raises(RuntimeError):
            async with audit.track("exploit", "exploit.bad", mission_id=workspace.id):
                msg = "fail"
                raise RuntimeError(msg)

        completed = await audit.get_entries(status="completed")
        failed = await audit.get_entries(status="failed")
        assert len(completed) == 1
        assert len(failed) == 1

    @pytest.mark.asyncio
    async def test_audit_context_fields(self, session, workspace) -> None:
        audit = AuditLogger(session)

        async with audit.track(
            "scan",
            "scanner.syn",
            mission_id=workspace.id,
            phase_id="phase_1",
            target="10.0.0.0/24",
            parameters={"ports": "1-1000"},
        ) as ctx:
            assert ctx.mission_id == workspace.id
            assert ctx.phase_id == "phase_1"
            assert ctx.action == "scan"
            ctx.result_summary = {"hosts_up": 42}

        entries = await audit.get_entries(mission_id=workspace.id)
        assert entries[0]["phase_id"] == "phase_1"

    @pytest.mark.asyncio
    async def test_get_entries_limit(self, session, workspace) -> None:
        audit = AuditLogger(session)

        for i in range(10):
            await audit.log("scan", f"scanner.port_{i}", mission_id=workspace.id)

        entries = await audit.get_entries(limit=5)
        assert len(entries) == 5

    @pytest.mark.asyncio
    async def test_no_mission_id(self, session) -> None:
        audit = AuditLogger(session)

        async with audit.track("scan", "scanner.tcp"):
            pass

        entries = await audit.get_entries()
        assert len(entries) == 1
        assert entries[0]["mission_id"] is None

    @pytest.mark.asyncio
    async def test_duration_recorded(self, session, workspace) -> None:
        audit = AuditLogger(session)

        async with audit.track("scan", "scanner.tcp", mission_id=workspace.id):
            pass

        entries = await audit.get_entries(mission_id=workspace.id)
        assert entries[0]["duration_ms"] is not None
        assert entries[0]["duration_ms"] >= 0
