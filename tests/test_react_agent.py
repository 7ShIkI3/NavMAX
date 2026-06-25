"""
Tests pour le ReAct Agent — boucle agentique Observe → Think → Act.
"""

import json

import pytest

from navmax.ai.react_agent import (
    ReActAgent,
    Tool,
    Step,
    StepUpdate,
    MissionResult,
    _make_default_tools,
    wire_tools,
)


# ── Mocks ────────────────────────────────────────────────────────


class MockAIEngine:
    """Simule l'AIEngine avec des réponses prédéfinies."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = responses or []
        self._idx = 0
        self.calls: list[str] = []

    async def generate(self, prompt: str, system_prompt: str = "", tier=None) -> str:
        self.calls.append(prompt)
        if self._idx < len(self.responses):
            resp = self.responses[self._idx]
            self._idx += 1
            return resp
        # Fallback: finish immédiatement
        return json.dumps({
            "thought": "Mission terminée.",
            "action": {"tool": "finish", "params": {"success": True, "summary": "Done."}},
        })

    async def stream(self, prompt: str, system_prompt: str = "", tier=None):
        for chunk in [self.responses[self._idx]] if self._idx < len(self.responses) else []:
            yield chunk


# ── Tests Tool ───────────────────────────────────────────────────


class TestTool:
    """Tests pour le dataclass Tool."""

    def test_creation(self):
        tool = Tool(
            name="test_tool",
            description="A test tool",
            parameters={"type": "object", "properties": {}},
            func=lambda x: x,
        )
        assert tool.name == "test_tool"
        assert tool.dangerous is False
        assert tool.requires_confirmation is False

    def test_dangerous_tool(self):
        tool = Tool(
            name="exploit",
            description="Run exploit",
            parameters={"type": "object", "properties": {}},
            func=lambda x: x,
            dangerous=True,
            requires_confirmation=True,
        )
        assert tool.dangerous is True
        assert tool.requires_confirmation is True

    def test_to_openai_tool(self):
        tool = Tool(
            name="scan",
            description="Scan ports",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP"}
                },
                "required": ["target"],
            },
            func=lambda t: t,
        )
        openai_tool = tool.to_openai_tool()
        assert openai_tool["type"] == "function"
        assert openai_tool["function"]["name"] == "scan"
        assert "target" in openai_tool["function"]["parameters"]["required"]

    async def test_async_func(self):
        """Tool avec une fonction async."""
        async def async_func(**kw):
            return {"result": "async_ok"}

        tool = Tool(
            name="async_tool",
            description="Async tool",
            parameters={"type": "object", "properties": {}},
            func=async_func,
        )
        result = await tool.func()
        assert result == {"result": "async_ok"}


# ── Tests _make_default_tools ──────────────────────────────────


class TestDefaultTools:
    """Vérifie que les tools par défaut sont bien formés."""

    def test_all_tools_have_required_fields(self):
        tools = _make_default_tools()
        assert len(tools) >= 5

        for tool in tools:
            assert tool.name, f"Tool sans nom: {tool}"
            assert tool.description, f"Tool {tool.name} sans description"
            assert isinstance(tool.parameters, dict), f"Tool {tool.name} params pas un dict"

    def test_dangerous_tools_marked(self):
        tools = _make_default_tools()
        dangerous = [t for t in tools if t.dangerous]
        assert len(dangerous) >= 2  # exploit, ad_enumerate, etc.

    def test_all_tools_serializable(self):
        for tool in _make_default_tools():
            openai_tool = tool.to_openai_tool()
            assert json.dumps(openai_tool)  # Doit être sérialisable sans erreur


# ── Tests ReActAgent ───────────────────────────────────────────


class TestReActAgent:
    """Tests de la boucle ReAct."""

    def test_init(self):
        engine = MockAIEngine()
        agent = ReActAgent(engine)
        assert agent.max_steps == 20
        assert len(agent.tools) >= 5
        assert "scan_ports" in agent.tools
        assert "finish" not in agent.tools  # finish n'est pas un tool

    def test_init_custom_max_steps(self):
        engine = MockAIEngine()
        agent = ReActAgent(engine, max_steps=5)
        assert agent.max_steps == 5

    def test_custom_tools(self):
        engine = MockAIEngine()
        custom_tool = Tool(
            name="custom",
            description="Custom tool",
            parameters={"type": "object", "properties": {}},
            func=lambda: "custom_result",
        )
        agent = ReActAgent(engine, tools=[custom_tool])
        assert "custom" in agent.tools
        assert len(agent.tools) == 1

    @pytest.mark.asyncio
    async def test_run_immediate_finish(self):
        """L'IA répond finish au premier step."""
        engine = MockAIEngine(responses=[
            json.dumps({
                "thought": "Rien à faire.",
                "action": {"tool": "finish", "params": {"success": True, "summary": "No targets."}},
            })
        ])
        agent = ReActAgent(engine, max_steps=5)

        result = await agent.run(objective="Test")

        assert isinstance(result, MissionResult)
        assert result.success is True
        assert result.total_steps == 1
        assert result.summary == "No targets."

    @pytest.mark.asyncio
    async def test_run_with_tool_call(self):
        """L'IA appelle un tool puis finish."""
        called_params = None

        async def my_tool(**kw):
            nonlocal called_params
            called_params = kw
            return {"ports": [80, 443], "services": ["http", "https"]}

        tool = Tool(
            name="scan_ports",
            description="Scan ports",
            parameters={
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"],
            },
            func=my_tool,
        )

        engine = MockAIEngine(responses=[
            # Step 1: appel scan
            json.dumps({
                "thought": "Je scanne la cible.",
                "action": {"tool": "scan_ports", "params": {"target": "10.0.0.1"}},
            }),
            # Step 2: finish
            json.dumps({
                "thought": "Scan terminé, ports 80 et 443 ouverts.",
                "action": {"tool": "finish", "params": {"success": True, "summary": "Ports 80, 443 found."}},
            }),
        ])
        agent = ReActAgent(engine, tools=[tool], max_steps=5)

        result = await agent.run(objective="Scan 10.0.0.1")

        assert result.success is True
        assert result.total_steps == 2
        assert called_params == {"target": "10.0.0.1"}

    @pytest.mark.asyncio
    async def test_run_max_steps_reached(self):
        """L'IA boucle sans jamais finish."""
        engine = MockAIEngine(responses=[
            json.dumps({
                "thought": f"Step {i}.",
                "action": {"tool": "scan_ports", "params": {"target": "10.0.0.1"}},
            })
            for i in range(10)
        ])
        agent = ReActAgent(engine, max_steps=3)

        result = await agent.run(objective="Boucle infinie")

        assert result.success is False
        assert result.total_steps == 3
        assert "Max steps" in result.summary

    @pytest.mark.asyncio
    async def test_run_unknown_tool(self):
        """L'IA appelle un tool qui n'existe pas."""
        engine = MockAIEngine(responses=[
            json.dumps({
                "thought": "J'appelle un tool inconnu.",
                "action": {"tool": "nonexistent_tool", "params": {}},
            }),
            json.dumps({
                "thought": "Échec, on abandonne.",
                "action": {"tool": "finish", "params": {"success": False, "summary": "Tool not found."}},
            }),
        ])
        agent = ReActAgent(engine, max_steps=5)

        result = await agent.run(objective="Test unknown tool")

        assert result.success is False
        assert result.steps[0].error is not None
        assert "inconnu" in result.steps[0].error.lower()

    @pytest.mark.asyncio
    async def test_run_tool_error(self):
        """Le tool lève une exception."""
        def failing_tool(**kw):
            raise RuntimeError("Tool crashed")

        tool = Tool(
            name="failing",
            description="Failing tool",
            parameters={"type": "object", "properties": {}},
            func=failing_tool,
        )
        engine = MockAIEngine(responses=[
            json.dumps({
                "thought": "Test du tool qui crash.",
                "action": {"tool": "failing", "params": {}},
            }),
            json.dumps({
                "thought": "Tool crashed, on abandonne.",
                "action": {"tool": "finish", "params": {"success": False, "summary": "Tool error."}},
            }),
        ])
        agent = ReActAgent(engine, tools=[tool], max_steps=5)

        result = await agent.run(objective="Test error")
        assert result.steps[0].error == "Tool crashed"


# ── Tests parsing ──────────────────────────────────────────────


class TestParsing:
    """Tests du parsing des réponses IA."""

    def _make_agent(self):
        from navmax.ai.react_agent import ReActAgent as RA
        return RA(MockAIEngine())

    def test_parse_pure_json(self):
        agent = self._make_agent()
        response = '{"thought": "OK", "action": {"tool": "finish", "params": {"success": true}}}'
        step = agent._parse_step(1, response)
        assert step.thought == "OK"
        assert step.tool_name == "finish"

    def test_parse_json_in_markdown_block(self):
        agent = self._make_agent()
        response = '```json\n{"thought": "OK", "action": {"tool": "finish", "params": {}}}\n```'
        step = agent._parse_step(1, response)
        assert step.thought == "OK"
        assert step.tool_name == "finish"

    def test_parse_json_with_text_prefix(self):
        agent = self._make_agent()
        response = 'Some text before {"thought": "OK", "action": {"tool": "finish", "params": {}}} and after'
        step = agent._parse_step(1, response)
        assert step.thought == "OK"

    def test_parse_invalid_json_raises(self):
        agent = self._make_agent()
        response = 'Not JSON at all'
        with pytest.raises(ValueError):
            agent._parse_step(1, response)


# ── Tests wire_tools ───────────────────────────────────────────


class TestWireTools:
    """Tests du branchement des tools."""

    def test_wire_nmap(self):
        engine = MockAIEngine()
        agent = ReActAgent(engine)

        class FakeNmapScanner:
            async def scan(self, target, ports="1-1000", profile="default"):
                from dataclasses import dataclass
                @dataclass
                class FakeHost:
                    ip: str
                    hostname: str = ""
                    os_match: str = ""
                    ports: list = []
                @dataclass
                class FakeResult:
                    hosts: list
                    duration_s: float
                return FakeResult(hosts=[FakeHost(ip=target)], duration_s=1.0)

        wire_tools(agent, nmap_scanner=FakeNmapScanner())
        assert "stub" not in repr(agent.tools["scan_ports"].func)

    def test_wire_all_stubs_unchanged_when_none(self):
        engine = MockAIEngine()
        agent = ReActAgent(engine)
        wire_tools(agent)  # No real scanners
        # Tous les tools restent des stubs


# ── Tests streaming ────────────────────────────────────────────


class TestStreaming:
    """Tests du streaming."""

    @pytest.mark.asyncio
    async def test_stream_run_finish_immediately(self):
        engine = MockAIEngine(responses=[
            json.dumps({
                "thought": "Done.",
                "action": {"tool": "finish", "params": {"success": True, "summary": "Quick finish."}},
            })
        ])
        agent = ReActAgent(engine, max_steps=5)

        updates = []
        async for update in agent.stream_run(objective="Test stream"):
            updates.append(update)

        assert len(updates) >= 2  # thinking + done
        assert updates[-1].status == "done"


# ── Tests Step / StepUpdate / MissionResult ─────────────────────


class TestDataClasses:
    """Tests des dataclasses."""

    def test_step_defaults(self):
        step = Step(step_number=1, thought="test", tool_name=None, tool_params=None, result=None, error=None)
        assert step.step_number == 1
        assert step.thought == "test"
        assert step.tool_name is None
        assert step.error is None
        assert step.timestamp is not None

    def test_step_update(self):
        update = StepUpdate(step_number=1, status="thinking", thought="Analyse...")
        assert update.status == "thinking"
        assert update.tool_name == ""

    def test_mission_result(self):
        result = MissionResult(
            objective="Test",
            success=True,
            steps=[],
            total_steps=0,
            duration_s=0.5,
            summary="OK",
            findings=[],
        )
        assert result.success is True
        assert result.duration_s == 0.5
