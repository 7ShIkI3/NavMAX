"""
Tests pour MissionPlanner — décomposition NL → phases exécutables.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from navmax.ai.mission_planner import (
    MissionPlanner, MissionPlan, MissionPhase, PhaseStatus,
    MISSION_PLANNER_SYSTEM, MISSION_PLANNER_TEMPLATE,
)
from navmax.ai.providers.base import GenerateResult, ProviderType, ModelTier


# ── Mock AIEngine ──────────────────────────────────────────────

def mock_engine(json_response: dict) -> AsyncMock:
    """Crée un AIEngine mock qui retourne le JSON spécifié."""
    engine = AsyncMock()
    engine.generate = AsyncMock(return_value=GenerateResult(
        text=json.dumps(json_response),
        model="mock-model",
        provider=ProviderType.OLLAMA,
        tokens_used=100,
        tokens_per_second=50.0,
        finish_reason="stop",
    ))
    return engine


# ── Tests: MissionPlan ─────────────────────────────────────────

class TestMissionPlan:
    def test_empty_plan(self):
        plan = MissionPlan(objective="test")
        assert plan.phase_count == 0
        assert plan.modules_used == []

    def test_topological_order_simple(self):
        plan = MissionPlan(objective="test", phases=[
            MissionPhase("p1", "Scan", "scanner"),
            MissionPhase("p2", "OSINT", "osint"),
            MissionPhase("p3", "Exploit", "exploit", depends_on=["p1", "p2"]),
        ])
        ordered = plan.topological_order()
        ids = [p.id for p in ordered]
        assert ids.index("p1") < ids.index("p3")
        assert ids.index("p2") < ids.index("p3")

    def test_topological_order_chain(self):
        plan = MissionPlan(objective="test", phases=[
            MissionPhase("p3", "Exploit", "exploit", depends_on=["p2"]),
            MissionPhase("p2", "OSINT", "osint", depends_on=["p1"]),
            MissionPhase("p1", "Scan", "scanner"),
        ])
        ordered = plan.topological_order()
        ids = [p.id for p in ordered]
        assert ids == ["p1", "p2", "p3"]

    def test_topological_order_parallel(self):
        plan = MissionPlan(objective="test", phases=[
            MissionPhase("p1", "Scan TCP", "scanner"),
            MissionPhase("p2", "OSINT DNS", "osint"),
            MissionPhase("p3", "Exploit", "exploit", depends_on=["p1", "p2"]),
        ])
        ordered = plan.topological_order()
        ids = [p.id for p in ordered]
        # p1 et p2 peuvent être dans n'importe quel ordre, mais p3 en dernier
        assert ids[-1] == "p3"
        assert "p1" in ids[:2]
        assert "p2" in ids[:2]

    def test_get_ready_phases(self):
        plan = MissionPlan(objective="test", phases=[
            MissionPhase("p1", "Scan", "scanner", status=PhaseStatus.COMPLETED),
            MissionPhase("p2", "Exploit", "exploit", depends_on=["p1"]),
            MissionPhase("p3", "Post", "exploit", depends_on=["p2"]),
        ])
        ready = plan.get_ready_phases()
        assert len(ready) == 1
        assert ready[0].id == "p2"

    def test_get_ready_phases_none(self):
        plan = MissionPlan(objective="test", phases=[
            MissionPhase("p1", "Exploit", "exploit", depends_on=["p_unknown"]),
        ])
        ready = plan.get_ready_phases()
        assert len(ready) == 0

    def test_modules_used(self):
        plan = MissionPlan(objective="test", phases=[
            MissionPhase("p1", "Scan", "scanner"),
            MissionPhase("p2", "OSINT", "osint"),
            MissionPhase("p3", "Scan again", "scanner"),
        ])
        assert sorted(plan.modules_used) == ["osint", "scanner"]


# ── Tests: MissionPhase ────────────────────────────────────────

class TestMissionPhase:
    def test_defaults(self):
        p = MissionPhase("p1", "Test phase", "scanner")
        assert p.status == PhaseStatus.PENDING
        assert p.result is None
        assert p.error is None
        assert p.depends_on == []
        assert p.parameters == {}


# ── Tests: MissionPlanner ──────────────────────────────────────

class TestMissionPlanner:
    @pytest.mark.asyncio
    async def test_plan_basic(self):
        engine = mock_engine({
            "phases": [
                {"id": "p1", "description": "Port scan", "module_needed": "scanner",
                 "parameters": {"ports": "1-1000"}, "depends_on": []},
                {"id": "p2", "description": "OSINT recon", "module_needed": "osint",
                 "parameters": {}, "depends_on": []},
                {"id": "p3", "description": "Exploit services", "module_needed": "exploit",
                 "parameters": {}, "depends_on": ["p1", "p2"]},
            ]
        })

        planner = MissionPlanner(engine)
        plan = await planner.plan("Audit network", target="10.0.0.0/24")

        assert plan.phase_count == 3
        assert plan.objective == "Audit network"
        assert plan.target == "10.0.0.0/24"
        assert "scanner" in plan.modules_used
        assert "osint" in plan.modules_used
        assert "exploit" in plan.modules_used

        # Verify generate was called with correct tier
        call_args = engine.generate.call_args
        assert call_args.kwargs["tier"] == ModelTier.MEDIUM
        assert call_args.kwargs["temperature"] == 0.3
        assert call_args.kwargs["json_mode"] is True

    @pytest.mark.asyncio
    async def test_plan_with_known_services(self):
        engine = mock_engine({
            "phases": [
                {"id": "p1", "description": "Exploit Redis", "module_needed": "exploit",
                 "parameters": {"port": 6379}, "depends_on": []},
            ]
        })

        planner = MissionPlanner(engine)
        plan = await planner.plan(
            "Exploit the Redis server",
            target="10.0.0.5",
            known_services=[{"host": "10.0.0.5", "port": 6379, "service": "redis"}],
        )

        assert plan.phase_count == 1
        # Prompt should include known services
        prompt_sent = engine.generate.call_args.kwargs["prompt"]
        assert "10.0.0.5:6379" in prompt_sent

    @pytest.mark.asyncio
    async def test_plan_with_constraints(self):
        engine = mock_engine({
            "phases": [
                {"id": "p1", "description": "Stealth scan", "module_needed": "scanner",
                 "parameters": {"stealth": True}, "depends_on": []},
            ]
        })

        planner = MissionPlanner(engine)
        plan = await planner.plan(
            "Scan the network quietly",
            target="10.0.0.0/24",
            constraints="No aggressive scanning, stay under radar",
        )
        prompt_sent = engine.generate.call_args.kwargs["prompt"]
        assert "stay under radar" in prompt_sent

    @pytest.mark.asyncio
    async def test_parse_json_wrapped_in_markdown(self):
        engine = AsyncMock()
        engine.generate = AsyncMock(return_value=GenerateResult(
            text='```json\n{"phases": [{"id": "p1", "description": "Scan", "module_needed": "scanner", "parameters": {}, "depends_on": []}]}\n```',
            model="mock",
            provider=ProviderType.OLLAMA,
            tokens_used=50,
            tokens_per_second=25.0,
            finish_reason="stop",
        ))

        planner = MissionPlanner(engine)
        plan = await planner.plan("test")
        assert plan.phase_count == 1

    @pytest.mark.asyncio
    async def test_parse_plain_json(self):
        engine = mock_engine({
            "phases": [
                {"id": "p1", "description": "Scan", "module_needed": "scanner",
                 "parameters": {}, "depends_on": []},
            ]
        })

        planner = MissionPlanner(engine)
        plan = await planner.plan("test")
        assert plan.phase_count == 1

    @pytest.mark.asyncio
    async def test_fallback_on_invalid_json(self):
        engine = AsyncMock()
        engine.generate = AsyncMock(return_value=GenerateResult(
            text="This is not JSON at all, just some text.",
            model="mock", provider=ProviderType.OLLAMA,
            tokens_used=10, tokens_per_second=5.0, finish_reason="stop",
        ))

        planner = MissionPlanner(engine)
        plan = await planner.plan("test", target="10.0.0.1")
        assert plan.phase_count == 3  # fallback plan
        assert plan.metadata.get("fallback") is True
        # Verify fallback phases exist
        modules = plan.modules_used
        assert "scanner" in modules
        assert "osint" in modules
        assert "exploit" in modules

    @pytest.mark.asyncio
    async def test_fallback_on_empty_phases(self):
        engine = mock_engine({"phases": []})
        planner = MissionPlanner(engine)
        plan = await planner.plan("test")
        assert plan.phase_count == 3  # fallback
        assert plan.metadata.get("fallback") is True

    @pytest.mark.asyncio
    async def test_system_prompt_included(self):
        engine = mock_engine({
            "phases": [{"id": "p1", "description": "Scan", "module_needed": "scanner",
                        "parameters": {}, "depends_on": []}]
        })

        planner = MissionPlanner(engine)
        await planner.plan("test")

        call_kwargs = engine.generate.call_args.kwargs
        assert call_kwargs["system"] == MISSION_PLANNER_SYSTEM

    @pytest.mark.asyncio
    async def test_plan_complex_objective(self):
        engine = mock_engine({
            "phases": [
                {"id": "p1", "description": "Port scan", "module_needed": "scanner",
                 "parameters": {"ports": "1-65535"}, "depends_on": []},
                {"id": "p2", "description": "DNS recon", "module_needed": "osint",
                 "parameters": {}, "depends_on": []},
                {"id": "p3", "description": "Web crawl", "module_needed": "proxy",
                 "parameters": {}, "depends_on": ["p1"]},
                {"id": "p4", "description": "Brute force SSH", "module_needed": "exploit",
                 "parameters": {"service": "ssh"}, "depends_on": ["p1"]},
            ]
        })

        planner = MissionPlanner(engine)
        plan = await planner.plan(
            "Find and exploit all entry points on target.com",
            target="target.com"
        )

        assert plan.phase_count == 4
        assert plan.target == "target.com"
        # Verify topological order
        ordered = plan.topological_order()
        ids = [p.id for p in ordered]
        assert ids.index("p1") < ids.index("p3")  # scan before web crawl
        assert ids.index("p1") < ids.index("p4")  # scan before exploit

    @pytest.mark.asyncio
    async def test_extract_json_from_text_with_prefix(self):
        """Test extraction quand l'IA préfixe avec du texte."""
        engine = AsyncMock()
        engine.generate = AsyncMock(return_value=GenerateResult(
            text='Here is the plan:\n\n{"phases": [{"id": "p1", "description": "Scan", "module_needed": "scanner", "parameters": {}, "depends_on": []}]}',
            model="mock", provider=ProviderType.OLLAMA,
            tokens_used=50, tokens_per_second=25.0, finish_reason="stop",
        ))

        planner = MissionPlanner(engine)
        plan = await planner.plan("test")
        assert plan.phase_count == 1
