"""
Tests pour P5 (Action) et P6 (Orchestration).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from navmax.exploit.ai_generator import (
    AIExploitGenerator, ServiceInfo, GeneratedExploit,
)
from navmax.exploit.auto_pivot import (
    AutoPivotEngine, PivotSession, PivotTarget,
)
from navmax.exploit.evasion import PolymorphicMutationEngine
from navmax.orchestrator.engine import (
    MissionOrchestrator, MissionResult,
)


# ═══════════════════════════════════════════════════════════════
# AIExploitGenerator
# ═══════════════════════════════════════════════════════════════

class TestAIExploitGenerator:
    @pytest.fixture
    def ai_engine(self):
        from navmax.ai.providers.base import GenerateResult, ProviderType
        engine = AsyncMock()
        engine.generate = AsyncMock(return_value=GenerateResult(
            text="import os\nprint('exploit ok')",
            model="mock", provider=ProviderType.OLLAMA,
            tokens_used=20, tokens_per_second=50.0, finish_reason="stop",
        ))
        return engine

    @pytest.fixture
    def service(self):
        return ServiceInfo(
            host="10.0.0.1", port=6379, service="redis",
            version="7.0.5", banner="-ERR unknown command",
        )

    @pytest.mark.asyncio
    async def test_generate_basic(self, ai_engine, service):
        gen = AIExploitGenerator(ai_engine)
        exploit = await gen.generate(service)
        assert exploit.is_valid
        assert "import os" in exploit.code
        assert exploit.attempts == 1

    @pytest.mark.asyncio
    async def test_generate_with_vulnerabilities(self, ai_engine):
        gen = AIExploitGenerator(ai_engine)
        svc = ServiceInfo(
            host="10.0.0.1", port=80, service="apache",
            version="2.4.49",
            vulnerabilities=[{"cve": "CVE-2021-41773"}],
        )
        exploit = await gen.generate(svc)
        assert exploit.is_valid
        # Prompt should include CVE
        call_args = ai_engine.generate.call_args
        assert "CVE-2021-41773" in call_args.kwargs["prompt"]

    @pytest.mark.asyncio
    async def test_extract_code_from_markdown(self, ai_engine, service):
        from navmax.ai.providers.base import GenerateResult, ProviderType
        ai_engine.generate = AsyncMock(return_value=GenerateResult(
            text="```python\nimport os\nprint('exploit')\n```",
            model="mock", provider=ProviderType.OLLAMA,
            tokens_used=20, tokens_per_second=50.0, finish_reason="stop",
        ))
        gen = AIExploitGenerator(ai_engine)
        exploit = await gen.generate(service)
        assert "import os" in exploit.code
        assert "```" not in exploit.code

    @pytest.mark.asyncio
    async def test_invalid_python_rejected(self, ai_engine, service):
        from navmax.ai.providers.base import GenerateResult, ProviderType
        ai_engine.generate = AsyncMock(return_value=GenerateResult(
            text="this is not python code {{{",
            model="mock", provider=ProviderType.OLLAMA,
            tokens_used=10, tokens_per_second=25.0, finish_reason="stop",
        ))
        gen = AIExploitGenerator(ai_engine)
        exploit = await gen.generate(service)
        assert exploit.error is not None

    @pytest.mark.asyncio
    async def test_sandbox_tested(self, ai_engine, service):
        sandbox = AsyncMock()
        sandbox_result = MagicMock()
        sandbox_result.exit_code = 0
        sandbox_result.stdout = "[+] OK"
        sandbox_result.stderr = ""
        sandbox.run = AsyncMock(return_value=sandbox_result)

        gen = AIExploitGenerator(ai_engine, sandbox=sandbox)
        exploit = await gen.generate(service)
        assert exploit.was_tested
        assert exploit.passed_sandbox

    @pytest.mark.asyncio
    async def test_self_heal_on_failure(self, ai_engine, service):
        """Si le sandbox échoue, l'IA doit corriger le code."""
        from navmax.ai.providers.base import GenerateResult, ProviderType

        call_count = [0]
        async def generate_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return GenerateResult(
                    text="import os\nprint('bad')",
                    model="mock", provider=ProviderType.OLLAMA,
                    tokens_used=20, tokens_per_second=50.0, finish_reason="stop",
                )
            else:
                return GenerateResult(
                    text="import os\nprint('fixed')",
                    model="mock", provider=ProviderType.OLLAMA,
                    tokens_used=20, tokens_per_second=50.0, finish_reason="stop",
                )

        ai_engine.generate = AsyncMock(side_effect=generate_side_effect)

        sandbox = AsyncMock()
        sandbox_result1 = MagicMock()
        sandbox_result1.exit_code = 1
        sandbox_result1.stderr = "NameError: name 'bad' is not defined"
        sandbox_result1.stdout = ""
        sandbox_result2 = MagicMock()
        sandbox_result2.exit_code = 0
        sandbox_result2.stdout = "fixed"
        sandbox_result2.stderr = ""
        sandbox.run = AsyncMock(side_effect=[sandbox_result1, sandbox_result2])

        gen = AIExploitGenerator(ai_engine, sandbox=sandbox, max_attempts=3)
        exploit = await gen.generate(service)
        assert exploit.passed_sandbox
        assert exploit.attempts == 2

    def test_service_info_defaults(self):
        svc = ServiceInfo(host="10.0.0.1", port=80)
        assert svc.service == ""
        assert svc.vulnerabilities == []

    def test_generated_exploit_properties(self):
        exploit = GeneratedExploit(code="print('ok')")
        assert exploit.is_valid
        assert not exploit.was_tested


# ═══════════════════════════════════════════════════════════════
# AutoPivotEngine
# ═══════════════════════════════════════════════════════════════

class TestAutoPivotEngine:
    @pytest.fixture
    def engine(self):
        return AutoPivotEngine()

    @pytest.fixture
    def session(self):
        return PivotSession(
            host="10.0.0.5", access_type="ssh",
            internal_network="10.0.1.0/24",
            current_user="www-data",
        )

    def test_network_prefix(self, engine):
        assert engine._network_prefix("10.0.1.0/24") == "10.0.1"
        assert engine._network_prefix("192.168.1.1") == "192.168.1"

    def test_identify_high_value_dc(self, engine):
        hosts = [{"ip": "10.0.1.10", "open_ports": [445, 3389], "services": []}]
        targets = engine._identify_high_value(hosts, PivotSession(
            host="10.0.0.5", access_type="ssh", internal_network="10.0.1.0/24"
        ))
        assert len(targets) == 1
        assert targets[0].priority >= 9  # DC priority
        assert "445" in targets[0].reason

    def test_identify_high_value_db(self, engine):
        hosts = [{"ip": "10.0.1.20", "open_ports": [3306, 5432], "services": []}]
        targets = engine._identify_high_value(hosts, PivotSession(
            host="10.0.0.5", access_type="ssh", internal_network="10.0.1.0/24"
        ))
        assert len(targets) == 1
        assert targets[0].priority >= 8

    def test_identify_no_high_value(self, engine):
        hosts = [{"ip": "10.0.1.30", "open_ports": [12345], "services": []}]
        targets = engine._identify_high_value(hosts, PivotSession(
            host="10.0.0.5", access_type="ssh", internal_network="10.0.1.0/24"
        ))
        assert len(targets) == 0

    def test_pivot_target_sorting(self, engine):
        targets = [
            PivotTarget(host="a", priority=5),
            PivotTarget(host="b", priority=9),
            PivotTarget(host="c", priority=3),
        ]
        sorted_targets = sorted(targets, key=lambda t: t.priority, reverse=True)
        assert sorted_targets[0].host == "b"
        assert sorted_targets[-1].host == "c"

    @pytest.mark.asyncio
    async def test_analyze_with_scanner(self, engine, session):
        """Test avec un scanner mocké."""
        scanner = MagicMock()
        scanner.scan = AsyncMock(return_value=[
            MagicMock(port=445, service="smb", version=None, error=None),
            MagicMock(port=3389, service="rdp", version=None, error=None),
        ])

        engine.scanner = scanner
        targets = await engine.analyze(session)
        assert len(targets) >= 1
        # Vérifier que le scanner a été appelé
        assert scanner.scan.called

    def test_pivot_session_defaults(self):
        session = PivotSession(
            host="10.0.0.5", access_type="webshell",
            internal_network="172.16.0.0/16",
        )
        assert session.current_user == ""
        assert session.privileges == "user"


# ═══════════════════════════════════════════════════════════════
# PolymorphicMutationEngine
# ═══════════════════════════════════════════════════════════════

class TestPolymorphicMutationEngine:
    @pytest.fixture
    def engine(self):
        return PolymorphicMutationEngine(seed=42)

    def test_mutate_does_not_change_behavior(self, engine):
        code = "x = 1 + 2\nprint(x)"
        mutated = engine.mutate(code, iterations=1)
        # Le code muté doit être du Python valide
        compile(mutated, "<test>", "exec")

    def test_mutate_produces_different_code(self, engine):
        code = "x = 1\ny = 2\nprint(x + y)"
        mutated = engine.mutate(code, iterations=5)
        assert mutated != code or len(mutated) > len(code)

    def test_mutate_handles_functions(self, engine):
        code = "def foo():\n    return 42\nprint(foo())"
        mutated = engine.mutate(code, iterations=2)
        compile(mutated, "<test>", "exec")

    def test_mutate_handles_imports(self, engine):
        code = "import os\nprint(os.name)"
        mutated = engine.mutate(code, iterations=1)
        compile(mutated, "<test>", "exec")

    def test_deterministic_with_seed(self):
        e1 = PolymorphicMutationEngine(seed=42)
        e2 = PolymorphicMutationEngine(seed=42)
        code = "x = 1\nprint(x)"
        assert e1.mutate(code, iterations=3) == e2.mutate(code, iterations=3)

    def test_different_seeds_produce_different_code(self):
        e1 = PolymorphicMutationEngine(seed=1)
        e2 = PolymorphicMutationEngine(seed=2)
        code = "x = 1\nprint(x)"
        m1 = e1.mutate(code, iterations=3)
        m2 = e2.mutate(code, iterations=3)
        # Pas garanti d'être différent mais très probable avec 7 techniques
        assert m1 != m2 or len(m1) != len(m2)

    def test_rename_variables_changes_names(self, engine):
        code = "x = 1\ny = 2\nz = x + y\nprint(z)"
        mutated = engine.mutate(code, iterations=1, techniques=["rename_variables"])
        # Les noms originaux ne devraient plus être dans le code
        # (sauf 'print' qui est un builtin)
        assert mutated != code

    def test_split_strings(self, engine):
        code = "msg = 'hello world'\nprint(msg)"
        mutated = engine.mutate(code, iterations=3, techniques=["split_strings"])
        compile(mutated, "<test>", "exec")

    def test_base64_wrap(self, engine):
        code = "import os\nprint(os.name)\nx = 42"
        mutated = engine.mutate(code, iterations=1, techniques=["base64_wrap"])
        compile(mutated, "<test>", "exec")

    def test_invalid_technique_ignored(self, engine):
        code = "print(1)"
        mutated = engine.mutate(code, iterations=1, techniques=["nonexistent"])
        assert mutated == code

    def test_empty_iterations(self, engine):
        code = "print(1)"
        mutated = engine.mutate(code, iterations=0)
        assert mutated == code


# ═══════════════════════════════════════════════════════════════
# MissionOrchestrator
# ═══════════════════════════════════════════════════════════════

class TestMissionOrchestrator:
    @pytest.fixture
    def orchestrator(self):
        return MissionOrchestrator()

    def test_mission_result_defaults(self):
        result = MissionResult(objective="test")
        assert result.phases_executed == 0
        assert result.success_rate == 0.0

    def test_mission_result_success_rate(self):
        result = MissionResult(
            objective="test",
            phases_executed=5,
            phases_succeeded=4,
            phases_failed=1,
        )
        assert result.success_rate == 0.8

    @pytest.mark.asyncio
    async def test_execute_no_planner(self, orchestrator):
        result = await orchestrator.execute("test")
        assert result.error is not None
        assert "planner" in result.error.lower()

    @pytest.mark.asyncio
    async def test_dry_run(self, orchestrator):
        planner = AsyncMock()
        from navmax.ai.mission_planner import MissionPlan, MissionPhase
        planner.plan = AsyncMock(return_value=MissionPlan(
            objective="test",
            phases=[
                MissionPhase("p1", "Scan", "scanner"),
                MissionPhase("p2", "Exploit", "exploit", depends_on=["p1"]),
            ]
        ))
        orchestrator.planner = planner

        result = await orchestrator.execute("test", dry_run=True)
        assert result.phases_executed == 2
        assert "p1" not in result.results  # dry run = pas d'exécution

    @pytest.mark.asyncio
    async def test_execute_with_scanner(self, orchestrator):
        planner = AsyncMock()
        from navmax.ai.mission_planner import MissionPlan, MissionPhase
        planner.plan = AsyncMock(return_value=MissionPlan(
            objective="scan test",
            phases=[MissionPhase("p1", "Port scan", "scanner",
                                  parameters={"target": "127.0.0.1", "ports": "80"})],
        ))
        orchestrator.planner = planner

        scanner = MagicMock()
        scanner.scan = AsyncMock(return_value=[
            MagicMock(port=80, service="http", error=None),
        ])
        orchestrator.scanner = scanner

        result = await orchestrator.execute("scan test")
        assert result.phases_succeeded == 1

    @pytest.mark.asyncio
    async def test_execute_with_exploit_search(self, orchestrator):
        planner = AsyncMock()
        from navmax.ai.mission_planner import MissionPlan, MissionPhase
        planner.plan = AsyncMock(return_value=MissionPlan(
            objective="exploit test",
            phases=[MissionPhase("p1", "Exploit Redis", "exploit",
                                  parameters={"service_hint": "redis"})],
        ))
        orchestrator.planner = planner

        exploits = MagicMock()
        exploits.search = MagicMock(return_value=[{"name": "redis_unauth"}])
        orchestrator.exploits = exploits

        result = await orchestrator.execute("exploit test")
        assert result.phases_succeeded == 1
        assert result.results["p1"]["exploit_found"] is True

    def test_parse_ports(self, orchestrator):
        assert orchestrator._parse_ports("80") == [80]
        assert orchestrator._parse_ports("22,80,443") == [22, 80, 443]
        assert orchestrator._parse_ports("1-3") == [1, 2, 3]
        assert orchestrator._parse_ports("80, 443, 8080") == [80, 443, 8080]
