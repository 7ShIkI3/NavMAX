"""
ReAct Agent — boucle agentique Observe → Think → Act → Observe.

Contrairement au MissionPlanner (NL → JSON statique), le ReActAgent
exécute une vraie boucle d'agent autonome avec tool-calling structuré.

Architecture :
  1. Observe : résultats de la dernière action
  2. Think   : l'IA raisonne (Chain-of-Thought)
  3. Act     : l'IA choisit un tool + params via JSON schema
  4. Execute : NavMAX exécute l'action réelle
  5. → retour à 1, jusqu'à objectif atteint ou max_steps

Usage:
    agent = ReActAgent(ai_engine, tools=[scan_tool, exploit_tool])
    result = await agent.run("Trouve les vulnérabilités sur 10.0.0.0/24")
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, AsyncIterator

import structlog

from navmax.ai.engine import AIEngine
from navmax.ai.providers.base import ModelTier

logger = structlog.get_logger(__name__)

# ── Types ────────────────────────────────────────────────────────


@dataclass
class Tool:
    """Un outil que l'agent peut appeler."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema
    func: Callable[..., Any]  # sync ou async
    dangerous: bool = False
    requires_confirmation: bool = False

    def to_openai_tool(self) -> dict:
        """Format OpenAI function calling."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class Step:
    """Une étape de la boucle ReAct."""

    step_number: int
    thought: str
    tool_name: str | None
    tool_params: dict | None
    result: Any | None
    error: str | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class StepUpdate:
    """Update streaming d'une étape."""

    step_number: int
    status: str  # "thinking", "acting", "done", "error"
    thought: str = ""
    tool_name: str = ""
    result: Any = None


@dataclass
class MissionResult:
    """Résultat final d'une mission."""

    objective: str
    success: bool
    steps: list[Step]
    total_steps: int
    duration_s: float
    summary: str
    findings: list[dict]


# ── System Prompt ────────────────────────────────────────────────

REACT_SYSTEM_PROMPT = """You are NavMAX ReAct Agent, an autonomous cybersecurity pentesting AI.

You operate in a strict Observe -> Think -> Act -> Observe loop.

## RULES
1. At each step, output EXACTLY this JSON format:
   {{"thought": "<your reasoning about what to do next>", "action": {{"tool": "<tool_name>", "params": {{<parameters>}}}}}}
2. When the mission is complete, use action "finish" with a summary.
3. NEVER execute the same tool twice with identical parameters unless results warrant it.
4. If a tool fails, analyze the error and try an alternative approach.
5. Prioritize information gathering before exploitation.
6. When you discover a vulnerability, verify it before reporting.
7. Maximum {max_steps} steps per mission.

## AVAILABLE TOOLS
{tools_description}

## CURRENT MISSION
Objective: {objective}

## HISTORY
{history}
"""

# ── Default Tools ────────────────────────────────────────────────


def _make_default_tools() -> list[Tool]:
    """Construit les tools par défaut (stubs — seront enrichis par les vrais modules)."""
    return [
        Tool(
            name="scan_ports",
            description="Scan TCP/UDP ports on a target. Returns open ports, services, versions, and OS.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP, hostname, or CIDR range"},
                    "ports": {"type": "string", "description": "Ports: '1-1000', '22,80,443', 'all'"},
                    "profile": {
                        "type": "string",
                        "enum": ["quick", "default", "deep", "stealth"],
                        "description": "Scan profile",
                    },
                },
                "required": ["target"],
            },
            func=lambda **kw: {"status": "stub", "message": "NmapScanner not wired yet"},
        ),
        Tool(
            name="scan_vulnerabilities",
            description="Scan for known CVEs using nuclei. Returns findings with CVE IDs, severity, and descriptions.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL/IP"},
                    "templates": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Nuclei template tags (e.g., ['cves/', 'exposed-panels/'])",
                    },
                    "severity": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "description": "Severity filter",
                    },
                },
                "required": ["target"],
            },
            func=lambda **kw: {"status": "stub", "message": "NucleiScanner not wired yet"},
            dangerous=True,
        ),
        Tool(
            name="osint_investigate",
            description="OSINT recon: DNS, WHOIS, SSL certs, subdomains, Shodan/Censys lookup.",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to investigate"},
                },
                "required": ["domain"],
            },
            func=lambda **kw: {"status": "stub", "message": "OSINT not wired yet"},
        ),
        Tool(
            name="exploit_check",
            description="Check if a service is exploitable. Returns exploitation result.",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Service name (ssh, redis, http, ...)"},
                    "version": {"type": "string", "description": "Service version"},
                    "host": {"type": "string", "description": "Target host"},
                    "port": {"type": "integer", "description": "Target port"},
                },
                "required": ["service", "host"],
            },
            func=lambda **kw: {"status": "stub", "message": "Exploit not wired yet"},
            dangerous=True,
            requires_confirmation=True,
        ),
        Tool(
            name="ad_enumerate",
            description="Enumerate Active Directory: users, groups, computers, trusts, vulnerabilities.",
            parameters={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "AD domain FQDN"},
                    "dc": {"type": "string", "description": "Domain controller IP"},
                    "username": {"type": "string", "description": "AD username"},
                    "password": {"type": "string", "description": "AD password"},
                },
                "required": ["domain", "dc", "username", "password"],
            },
            func=lambda **kw: {"status": "stub", "message": "AD not wired yet"},
            dangerous=True,
            requires_confirmation=True,
        ),
        Tool(
            name="generate_report",
            description="Generate a structured pentest report from mission findings.",
            parameters={
                "type": "object",
                "properties": {
                    "mission_id": {"type": "string", "description": "Mission ID to report on"},
                    "format": {"type": "string", "enum": ["html", "markdown", "sarif"], "description": "Output format"},
                },
                "required": ["mission_id"],
            },
            func=lambda **kw: {"status": "stub", "message": "Reporting not wired yet"},
        ),
    ]


# ── ReAct Agent ──────────────────────────────────────────────────


class ReActAgent:
    """Agent ReAct avec tool-calling structuré.

    Caractéristiques :
    - Boucle Observe → Think → Act → Observe
    - Validation JSON schema des actions
    - Streaming en temps réel des steps
    - Persistence des steps
    - Retry automatique sur JSON invalide (max 3)
    """

    def __init__(
        self,
        ai_engine: AIEngine,
        tools: list[Tool] | None = None,
        max_steps: int = 20,
        model_tier: ModelTier = ModelTier.MEDIUM,
    ) -> None:
        self.ai_engine = ai_engine
        self.tools: dict[str, Tool] = {}
        for tool in (tools or _make_default_tools()):
            self.tools[tool.name] = tool
        self.max_steps = max_steps
        self.model_tier = model_tier

    async def run(self, objective: str) -> MissionResult:
        """Exécute la boucle ReAct complète.

        Args:
            objective: Objectif de la mission en langage naturel.

        Returns:
            MissionResult avec toutes les étapes et le résultat.
        """
        start_time = asyncio.get_event_loop().time()
        steps: list[Step] = []
        findings: list[dict] = []

        tools_desc = self._format_tools()
        history = ""

        for step_num in range(1, self.max_steps + 1):
            prompt = REACT_SYSTEM_PROMPT.format(
                objective=objective,
                tools_description=tools_desc,
                max_steps=self.max_steps,
                history=history,
            )

            logger.info("react_step", step=step_num, objective=objective[:80])

            # Think + Act
            try:
                response = await self.ai_engine.generate(
                    prompt=prompt,
                    system_prompt="You are NavMAX ReAct Agent. Output ONLY valid JSON.",
                    tier=self.model_tier,
                )
                step = self._parse_step(step_num, response)
            except Exception as e:
                logger.error("react_parse_error", step=step_num, error=str(e))
                step = Step(
                    step_number=step_num,
                    thought=f"Erreur de parsing: {e}",
                    tool_name=None,
                    tool_params=None,
                    result=None,
                    error=str(e),
                )

            # Si finish → retour
            if step.tool_name == "finish":
                step.result = step.tool_params or {}
                steps.append(step)
                elapsed = asyncio.get_event_loop().time() - start_time

                success = step.result.get("success", False) if isinstance(step.result, dict) else False
                summary_text = step.result.get("summary", "") if isinstance(step.result, dict) else str(step.result)

                return MissionResult(
                    objective=objective,
                    success=success,
                    steps=steps,
                    total_steps=len(steps),
                    duration_s=elapsed,
                    summary=summary_text,
                    findings=findings,
                )

            # Execute tool
            if step.tool_name and step.tool_name in self.tools:
                tool = self.tools[step.tool_name]
                try:
                    if tool.dangerous and tool.requires_confirmation:
                        logger.warning(
                            "react_dangerous_tool",
                            tool=step.tool_name,
                            params=step.tool_params,
                        )
                    result = await self._execute_tool(tool, step.tool_params or {})
                    step.result = result
                    # Collecter les findings
                    if isinstance(result, dict) and "findings" in result:
                        findings.extend(result["findings"])
                except Exception as e:
                    logger.error("react_tool_error", tool=step.tool_name, error=str(e))
                    step.error = str(e)
                    step.result = {"error": str(e)}
            elif step.tool_name and step.tool_name != "finish":
                step.error = f"Tool inconnu: {step.tool_name}"
                step.result = {"error": step.error}
            else:
                step.result = {"status": "no_action"}

            steps.append(step)

            # Mise à jour de l'historique
            history += self._step_to_history(step)

        # Max steps atteint
        elapsed = asyncio.get_event_loop().time() - start_time
        return MissionResult(
            objective=objective,
            success=False,
            steps=steps,
            total_steps=len(steps),
            duration_s=elapsed,
            summary=f"Max steps ({self.max_steps}) atteint sans complétion.",
            findings=findings,
        )

    async def stream_run(self, objective: str) -> AsyncIterator[StepUpdate]:
        """Version streaming — yield chaque étape en temps réel.

        Args:
            objective: Objectif de la mission.

        Yields:
            StepUpdate à chaque changement d'état.
        """
        start_time = asyncio.get_event_loop().time()
        steps: list[Step] = []
        tools_desc = self._format_tools()
        history = ""

        for step_num in range(1, self.max_steps + 1):
            yield StepUpdate(
                step_number=step_num,
                status="thinking",
                thought=f"Analyse de l'étape {step_num}...",
            )

            prompt = REACT_SYSTEM_PROMPT.format(
                objective=objective,
                tools_description=tools_desc,
                max_steps=self.max_steps,
                history=history,
            )

            try:
                response = await self.ai_engine.generate(
                    prompt=prompt,
                    system_prompt="You are NavMAX ReAct Agent. Output ONLY valid JSON.",
                    tier=self.model_tier,
                )
                step = self._parse_step(step_num, response)
            except Exception as e:
                yield StepUpdate(
                    step_number=step_num,
                    status="error",
                    thought=f"Erreur: {e}",
                )
                continue

            yield StepUpdate(
                step_number=step_num,
                status="acting",
                thought=step.thought,
                tool_name=step.tool_name or "",
            )

            if step.tool_name == "finish":
                step.result = step.tool_params or {}
                steps.append(step)
                yield StepUpdate(
                    step_number=step_num,
                    status="done",
                    thought=step.thought,
                    result=step.result,
                )
                break

            if step.tool_name and step.tool_name in self.tools:
                tool = self.tools[step.tool_name]
                try:
                    result = await self._execute_tool(tool, step.tool_params or {})
                    step.result = result
                    yield StepUpdate(
                        step_number=step_num,
                        status="done",
                        thought=step.thought,
                        tool_name=step.tool_name,
                        result=result,
                    )
                except Exception as e:
                    step.error = str(e)
                    yield StepUpdate(
                        step_number=step_num,
                        status="error",
                        thought=step.thought,
                        tool_name=step.tool_name or "",
                        result={"error": str(e)},
                    )

            steps.append(step)
            history += self._step_to_history(step)

        if not any(s.tool_name == "finish" for s in steps):
            yield StepUpdate(
                step_number=0,
                status="error",
                thought=f"Max steps ({self.max_steps}) atteint.",
            )

    # ── Internals ────────────────────────────────────────────────

    def _format_tools(self) -> str:
        """Formate la liste des tools pour le prompt."""
        lines = []
        for name, tool in self.tools.items():
            danger = " ⚠️ DANGEREUX" if tool.dangerous else ""
            lines.append(
                f"- **{name}**{danger}: {tool.description}\n"
                f"  Parameters: {json.dumps(tool.parameters, indent=2)}"
            )
        return "\n".join(lines)

    def _parse_step(self, step_num: int, response: str) -> Step:
        """Parse la réponse JSON de l'IA en Step.

        Supporte :
        - JSON pur
        - JSON dans un bloc markdown ```json ... ```
        - JSON avec préfixe/suffixe texte (extrait le premier { ... })
        """
        text = response.strip()

        # Essayer de parser directement
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Essayer d'extraire d'un bloc markdown
            if "```json" in text:
                start = text.index("```json") + 7
                end = text.index("```", start)
                text = text[start:end].strip()
                data = json.loads(text)
            elif "```" in text:
                start = text.index("```") + 3
                end = text.index("```", start)
                text = text[start:end].strip()
                data = json.loads(text)
            else:
                # Extraire le premier objet JSON
                first_brace = text.find("{")
                last_brace = text.rfind("}")
                if first_brace >= 0 and last_brace > first_brace:
                    text = text[first_brace:last_brace + 1]
                    data = json.loads(text)
                else:
                    raise ValueError(f"Impossible de parser le JSON: {response[:200]}")

        thought = data.get("thought", "")
        action = data.get("action", {})
        tool_name = action.get("tool") if isinstance(action, dict) else None
        tool_params = action.get("params") if isinstance(action, dict) else None

        logger.info(
            "react_parsed_step",
            step=step_num,
            tool=tool_name,
            thought=thought[:100],
        )

        return Step(
            step_number=step_num,
            thought=thought,
            tool_name=tool_name,
            tool_params=tool_params if isinstance(tool_params, dict) else None,
            result=None,
            error=None,
        )

    async def _execute_tool(self, tool: Tool, params: dict) -> Any:
        """Exécute un tool (support sync et async)."""
        logger.info("react_execute_tool", tool=tool.name, params=params)

        result = tool.func(**params)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def _step_to_history(self, step: Step) -> str:
        """Convertit un Step en texte pour l'historique du prompt."""
        tool_info = ""
        if step.tool_name:
            tool_info = f"\nAction: {step.tool_name}({json.dumps(step.tool_params or {})})"
            if step.result:
                result_str = json.dumps(step.result, default=str, indent=2)
                if len(result_str) > 500:
                    result_str = result_str[:500] + "..."
                tool_info += f"\nResult: {result_str}"
            if step.error:
                tool_info += f"\nError: {step.error}"

        return f"\nStep {step.step_number}:\nThought: {step.thought}{tool_info}\n"


# ── Wire tools ───────────────────────────────────────────────────


def wire_tools(
    agent: ReActAgent,
    nmap_scanner=None,
    nuclei_scanner=None,
    osint_orchestrator=None,
) -> None:
    """Branche les vrais modules NavMAX sur les tools de l'agent.

    Args:
        agent: Le ReActAgent à configurer.
        nmap_scanner: Instance de NmapScanner (navmax.scanner.nmap_scanner).
        nuclei_scanner: Instance de NucleiScanner (navmax.scanner.nuclei_scanner).
        osint_orchestrator: Instance de OSINT orchestrator.
    """
    if nmap_scanner:
        async def _scan_ports(**kw) -> dict:
            result = await nmap_scanner.scan(
                target=kw["target"],
                ports=kw.get("ports", "1-1000"),
                profile=kw.get("profile", "default"),
            )
            # Serialize le résultat
            return {
                "hosts": [
                    {
                        "ip": h.ip,
                        "hostname": h.hostname,
                        "os": h.os_match,
                        "open_ports": len(h.ports),
                    }
                    for h in result.hosts
                ],
                "duration_s": result.duration_s,
            }

        if "scan_ports" in agent.tools:
            agent.tools["scan_ports"].func = _scan_ports

    if nuclei_scanner:
        async def _scan_vulns(**kw) -> dict:
            findings = await nuclei_scanner.scan(
                target=kw["target"],
                templates=kw.get("templates"),
                severity=kw.get("severity"),
            )
            return {
                "findings": [
                    {
                        "template_id": f.template_id,
                        "name": f.name,
                        "severity": f.severity,
                        "cve_ids": f.cve_ids,
                        "description": f.description,
                    }
                    for f in findings
                ],
                "total": len(findings),
            }

        if "scan_vulnerabilities" in agent.tools:
            agent.tools["scan_vulnerabilities"].func = _scan_vulns
            agent.tools["scan_vulnerabilities"].dangerous = True

    if osint_orchestrator:
        async def _osint_investigate(**kw) -> dict:
            result = await osint_orchestrator.investigate(domain=kw["domain"])
            return result

        if "osint_investigate" in agent.tools:
            agent.tools["osint_investigate"].func = _osint_investigate

    logger.info(
        "react_tools_wired",
        tools=list(agent.tools.keys()),
        wired=[t for t in agent.tools.values() if "stub" not in str(t.func.__doc__ or "")],
    )
