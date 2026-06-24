"""Tests du module workspace."""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from navmax.db.models import Base, Workspace, Target
from navmax.workspace import WorkspaceManager


@pytest.fixture
async def session():
    """Session SQLite en mémoire pour les tests."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
class TestWorkspaceManager:
    """Tests CRUD du workspace manager."""

    async def test_create(self, session):
        mgr = WorkspaceManager(session)
        ws = await mgr.create("Projet Alpha", "Audit du réseau interne")
        assert ws.name == "Projet Alpha"
        assert ws.description == "Audit du réseau interne"
        assert ws.id is not None

    async def test_get(self, session):
        mgr = WorkspaceManager(session)
        ws = await mgr.create("Beta")
        found = await mgr.get(ws.id)
        assert found is not None
        assert found.name == "Beta"

    async def test_list_all(self, session):
        mgr = WorkspaceManager(session)
        await mgr.create("WS1")
        await mgr.create("WS2")
        all_ws = await mgr.list_all()
        assert len(all_ws) == 2

    async def test_update(self, session):
        mgr = WorkspaceManager(session)
        ws = await mgr.create("Old Name", "Old Desc")
        updated = await mgr.update(ws.id, name="New Name", description="New Desc")
        assert updated is not None
        assert updated.name == "New Name"
        assert updated.description == "New Desc"

    async def test_delete(self, session):
        mgr = WorkspaceManager(session)
        ws = await mgr.create("To Delete")
        ok = await mgr.delete(ws.id)
        assert ok is True
        assert await mgr.get(ws.id) is None

    async def test_delete_nonexistent(self, session):
        mgr = WorkspaceManager(session)
        ok = await mgr.delete("nonexistent-id")
        assert ok is False

    async def test_stats(self, session):
        mgr = WorkspaceManager(session)
        ws = await mgr.create("Stats WS")
        stats = await mgr.get_stats(ws.id)
        assert stats["name"] == "Stats WS"
        assert stats["target_count"] == 0

    async def test_add_remove_target(self, session):
        mgr = WorkspaceManager(session)
        ws = await mgr.create("WS with targets")

        target = Target(
            id="t1", name="test-host", address="192.168.1.1", kind="host"
        )
        session.add(target)
        await session.flush()

        # Associate
        ok = await mgr.add_target(ws.id, "t1")
        assert ok is True

        targets = await mgr.list_targets(ws.id)
        assert len(targets) == 1
        assert targets[0].name == "test-host"

        # Disassociate
        ok = await mgr.remove_target(ws.id, "t1")
        assert ok is True

        targets = await mgr.list_targets(ws.id)
        assert len(targets) == 0

    async def test_get_nonexistent(self, session):
        mgr = WorkspaceManager(session)
        assert await mgr.get("fake-id") is None

    async def test_update_nonexistent(self, session):
        mgr = WorkspaceManager(session)
        assert await mgr.update("fake-id", name="x") is None
