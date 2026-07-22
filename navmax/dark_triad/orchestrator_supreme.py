"""Dark Triad — Orchestrateur Suprême (ULTIMATE).

Manager IA monstrueusement intelligent. Analyse l'objectif via LLM,
décide quels agents spawner, adapte la stratégie en temps réel,
gère les sous-agents dynamiquement. Les 3 personnalités dictent
TOUT le comportement — pas juste cosmétique.

NARCISSUS   → agressif, parallèle, confiance absolue, jamais ne vérifie
PSYCHOPATH  → tous les agents en parallèle, force brute, zéro limite
MACHIAVELLI → stratégique, séquentiel intelligent, furtif, vérification
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from navmax.dark_triad.base import AgentResult, BaseAgent
from navmax.dark_triad.registry import AgentRegistry
from navmax.dark_triad.ai_router import AIRouter
from navmax.dark_triad.personality import (
    MACHIAVELLI, NARCISSUS, PSYCHOPATH,
    AggressionLevel, PersonalityMode, PersonalityProfile,
)
from navmax.dark_triad.sandbox import SandboxManager
from navmax.dark_triad.battle_manager import BattleManager, BattleReport
from navmax.dark_triad.mission_planner import MissionPlanner
from navmax.dark_triad.shared import MissionPlan, MissionPhase, PhaseResult, PhaseStatus

logger = structlog.get_logger(__name__)


# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class AgentTeam:
    """Groupe d'agents assignés à une phase."""
    phase: MissionPhase
    primary: BaseAgent
    support: list[BaseAgent] = field(default_factory=list)
    sub_agents: list[BaseAgent] = field(default_factory=list)


@dataclass
class StrategyDecision:
    """Décision stratégique prise par l'orchestrateur."""
    action: str  # spawn, wait, pivot, escalate, abort, stealth
    reasoning: str
    agents_to_spawn: list[str] = field(default_factory=list)
    target: str = ""
    priority: int = 5  # 1-10
    confidence: float = 0.5


@dataclass
class OrchestratorState:
    """État courant de la mission."""
    objective: str
    personality: str
    phase: str = "planning"  # planning, executing, adapting, exfiltrating, done
    agents_active: int = 0
    findings_count: int = 0
    risk_level: float = 0.0
    detection_probability: float = 0.0
    decisions_made: int = 0
    sub_agents_spawned: int = 0


# ── Orchestrateur ────────────────────────────────────────────────────────────

class DarkTriadOrchestrator:
    """Orchestrateur IA suprême — cerveau de l'opération.

    Utilise le LLM pour :
    - Analyser l'objectif et choisir la stratégie
    - Décider dynamiquement quels agents spawner
    - Adapter en temps réel selon les résultats
    - Gérer les sous-agents et la furtivité
    """

    # Mapping personnalité → comportement
    PERSONALITY_BEHAVIORS = {
        "narcissism": {
            "max_parallel": 10, "verify": False, "stealth": False,
            "retry_on_fail": False, "spawn_subs": True,
            "aggression": "maximum", "style": "Blitzkrieg — tout, tout de suite",
        },
        "psychopathy": {
            "max_parallel": 50, "verify": False, "stealth": False,
            "retry_on_fail": True, "spawn_subs": True,
            "aggression": "relentless", "style": "Apocalypse — aucune limite",
        },
        "mach": {
            "max_parallel": 3, "verify": True, "stealth": True,
            "retry_on_fail": False, "spawn_subs": False,
            "aggression": "strategic", "style": "Ghost — invisible, méthodique",
        },
    }

    def __init__(self, ai_router: AIRouter | None = None):
        self.ai_router = ai_router
        self.registry = AgentRegistry()
        self.sandbox = SandboxManager()
        self.state: OrchestratorState | None = None
        self.decisions: list[StrategyDecision] = []
        self._battle_manager: BattleManager | None = None
        self._log = structlog.get_logger("tdt.orchestrator")

    # ── Public API ────────────────────────────────────────────────────────

    async def execute_mission(self, objective: str,
                               persona: str = "mach") -> dict[str, Any]:
        """Exécute une mission complète avec intelligence adaptative."""
        start = time.monotonic()
        profile = self._get_profile(persona)
        behavior = self.PERSONALITY_BEHAVIORS[persona]

        # Init state
        self.state = OrchestratorState(
            objective=objective, personality=persona,
            risk_level={"narcissism": 0.8, "psychopathy": 0.95, "mach": 0.2}[persona],
        )

        # ── Phase 1: Analyse stratégique LLM ────────────────────────────
        strategy = await self._analyze_strategy(objective, persona)
        self.decisions.append(strategy)
        self.state.decisions_made += 1

        # ── Phase 2: Bootstrap agents ───────────────────────────────────
        await self._bootstrap_agents(persona, behavior)

        # ── Phase 3: Planification ──────────────────────────────────────
        plan = await self._create_plan(objective, persona)

        # ── Phase 4: Exécution adaptative ───────────────────────────────
        self._battle_manager = BattleManager(self.registry, self.sandbox)
        self.state.phase = "executing"

        report = await self._battle_manager.execute_plan(plan)
        self.state.agents_active = len(self.registry.list_all())
        self.state.findings_count = sum(
            1 for r in report.phase_results if r.status == PhaseStatus.COMPLETED)

        # ── Phase 5: Sous-agents (si personnalité le permet) ────────────
        if behavior["spawn_subs"] and persona in ("narcissism", "psychopathy"):
            subs = await self._spawn_sub_agents(objective, report, persona)
            self.state.sub_agents_spawned = len(subs)

        # ── Phase 6: Adaptation en temps réel ───────────────────────────
        if report.phases_failed > 0 and behavior["retry_on_fail"]:
            self.state.phase = "adapting"
            adapt = await self._adapt_strategy(objective, report, persona)
            self.decisions.append(adapt)

        # ── Phase 7: Exfiltration furtive (Machiavellian) ───────────────
        if behavior["stealth"]:
            self.state.phase = "exfiltrating"
            await self._stealth_exfil(report)

        self.state.phase = "done"
        return {
            "success": report.success,
            "phases_completed": f"{report.phases_completed}/{report.phases_total}",
            "phases_failed": report.phases_failed,
            "sub_agents_spawned": self.state.sub_agents_spawned,
            "decisions_made": self.state.decisions_made,
            "detection_probability": self.state.detection_probability,
            "duration_ms": (time.monotonic() - start) * 1000,
            "personality_style": behavior["style"],
            "phase_results": [
                {"name": r.phase_id, "agent": r.agent_name,
                 "status": r.status.value, "output": (r.output or "")[:200]}
                for r in report.phase_results
            ],
            "strategy": strategy.reasoning[:200],
        }

    # ── Strategic Analysis (LLM-powered) ─────────────────────────────────

    async def _analyze_strategy(self, objective: str,
                                 persona: str) -> StrategyDecision:
        """Utilise le LLM pour analyser l'objectif et choisir la stratégie."""
        if not self.ai_router:
            # Fallback: heuristiques
            return StrategyDecision(
                action="spawn",
                reasoning=f"Heuristic strategy for {persona}: spawn all agents",
                agents_to_spawn=["recon", "exploit", "post_exploit", "privesc"],
                confidence=0.7,
            )

        behavior = self.PERSONALITY_BEHAVIORS[persona]
        prompt = f"""Tu es l'orchestrateur Dark Triad en mode {persona.upper()}.
Style de combat : {behavior['style']}
Objectif : {objective}

Analyse l'objectif et décide de la stratégie optimale.
Réponds UNIQUEMENT en JSON :
{{"action": "spawn|wait|stealth|pivot", "reasoning": "...",
  "agents": ["recon","exploit","privesc","jailbreak","post_exploit","evader"],
  "priority": 1-10, "target": "..."}}"""

        try:
            result = await self.ai_router.generate(
                prompt, personality=persona,
            )
            data = json.loads(result.text if hasattr(result, 'text') else str(result))
            return StrategyDecision(
                action=data.get("action", "spawn"),
                reasoning=data.get("reasoning", "Strategic analysis"),
                agents_to_spawn=data.get("agents", ["recon", "exploit"]),
                priority=data.get("priority", 5),
                confidence=0.8,
            )
        except Exception:
            return StrategyDecision(
                action="spawn",
                reasoning="LLM analysis failed — fallback to full spawn",
                agents_to_spawn=["recon", "exploit", "post_exploit", "privesc", "jailbreak"],
                confidence=0.5,
            )

    # ── Agent Bootstrap ───────────────────────────────────────────────────

    async def _bootstrap_agents(self, persona: str,
                                 behavior: dict) -> None:
        """Enregistre les agents selon la personnalité."""
        from navmax.dark_triad.bootstrap import bootstrap_agents
        bootstrap_agents(self.registry, self.ai_router)

    # ── Plan Creation ─────────────────────────────────────────────────────

    async def _create_plan(self, objective: str,
                            persona: str) -> MissionPlan:
        """Crée un plan de mission avec le LLM."""
        planner = MissionPlanner(self.ai_router, self.registry, self.sandbox)
        try:
            return await planner.plan(
                objective=objective,
                personality=persona,
                constraints={"aggression": self.PERSONALITY_BEHAVIORS[persona]["aggression"]},
            )
        except Exception:
            # Fallback: plan minimal
            phases = [
                MissionPhase(id="recon", phase_number=1, name="reconnaissance",
                             agent_name="ReconAgent_mach", agent_category="recon",
                             objective=f"Scan target from: {objective}"),
                MissionPhase(id="exploit", phase_number=2, name="exploitation",
                             agent_name="ExploiterAgent_mach", agent_category="exploit",
                             objective=f"Exploit services on target"),
            ]
            return MissionPlan(objective=objective, personality=persona, phases=phases)

    # ── Sub-agents ────────────────────────────────────────────────────────

    async def _spawn_sub_agents(self, objective: str,
                                 report: BattleReport,
                                 persona: str) -> list[BaseAgent]:
        """Spawn des sous-agents spécialisés basés sur les résultats."""
        spawned: list[BaseAgent] = []
        if not self.ai_router:
            return spawned

        # Pour chaque phase réussie, spawn un sous-agent spécialisé
        for pr in report.phase_results:
            if pr.status != PhaseStatus.COMPLETED:
                continue

            # Créer un sous-agent léger pour approfondir
            sub = await self._create_sub_agent(pr, persona)
            if sub:
                self.registry.register(sub)
                spawned.append(sub)
                self._log.info("sub_agent_spawned", name=sub.name, parent=pr.phase_id)

        return spawned

    async def _create_sub_agent(self, phase_result: PhaseResult,
                                 persona: str) -> BaseAgent | None:
        """Crée un sous-agent spécialisé pour une phase."""
        from navmax.dark_triad.recon import ReconAgent
        from navmax.dark_triad.exploiter import ExploiterAgent
        from navmax.dark_triad.privesc import PrivescAgent

        profile = self._get_profile(persona)
        agent_type = {
            "recon": ReconAgent, "exploit": ExploiterAgent,
            "privesc": PrivescAgent,
        }.get(phase_result.phase_id.split("_")[0] if "_" in phase_result.phase_id else "recon")

        if not agent_type:
            return None

        return agent_type(
            name=f"Sub_{agent_type.__name__}_{int(time.time()) % 10000}",
            personality=profile,
            ai_router=self.ai_router,
            sandbox=self.sandbox,
        )

    # ── Adaptation ────────────────────────────────────────────────────────

    async def _adapt_strategy(self, objective: str,
                               report: BattleReport,
                               persona: str) -> StrategyDecision:
        """Adapte la stratégie basée sur les résultats."""
        if not self.ai_router:
            return StrategyDecision(action="wait", reasoning="No LLM for adaptation")

        failed = [r for r in report.phase_results if r.status == PhaseStatus.FAILED]
        prompt = f"""Mission en cours. {len(failed)} phases ont échoué.
Objectif: {objective}
Échecs: {', '.join(r.phase_id for r in failed[:5])}

Décide de la prochaine action. Réponds UNIQUEMENT en JSON :
{{"action": "retry|skip|escalate|abort", "reasoning": "...", "priority": 1-10}}"""

        try:
            result = await self.ai_router.generate(prompt, personality=persona)
            data = json.loads(str(result.text) if hasattr(result, 'text') else str(result))
            return StrategyDecision(
                action=data.get("action", "skip"),
                reasoning=data.get("reasoning", "Adaptive response"),
                priority=data.get("priority", 3),
            )
        except Exception:
            return StrategyDecision(action="skip", reasoning="Adaptation failed")

    # ── Stealth Exfil ─────────────────────────────────────────────────────

    async def _stealth_exfil(self, report: BattleReport) -> None:
        """Exfiltration furtive — minimise les traces."""
        # Simuler une exfiltration lente et discrète
        self.state.detection_probability = min(
            self.state.detection_probability + 0.05, 0.3)
        await asyncio.sleep(0.5)  # Délai de furtivité
        self._log.info("stealth_exfil_complete",
                       findings=report.phases_completed,
                       detection_risk=f"{self.state.detection_probability:.0%}")

    # ── Helpers ───────────────────────────────────────────────────────────

    def _get_profile(self, persona: str) -> PersonalityProfile:
        return {"narcissism": NARCISSUS, "psychopathy": PSYCHOPATH, "mach": MACHIAVELLI}.get(persona, MACHIAVELLI)
