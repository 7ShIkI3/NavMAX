"""Bootstrap 18 Dark Triad agents into the registry."""

import asyncio
import json
import time
from pathlib import Path

from navmax.dark_triad import (
    AgentRegistry,
    BattleManager,
    MACHIAVELLI,
    MissionPlan,
    NARCISSUS,
    PSYCHOPATH,
)
from navmax.dark_triad.ai_router import AIRouter
from navmax.dark_triad.recon import ReconAgent
from navmax.dark_triad.exploiter import ExploiterAgent
from navmax.dark_triad.post_exploit import PostExploitAgent
from navmax.dark_triad.evader import EvaderAgent
from navmax.dark_triad.ad_specialist import ADSpecialistAgent
from navmax.dark_triad.privesc import PrivescAgent
from navmax.dark_triad.jailbreak import JailbreakAgent
from navmax.dark_triad.sandbox import SandboxManager

_PROVIDERS_FILE = Path.home() / ".tdt" / "providers.json"


def bootstrap_agents(registry: AgentRegistry, router: AIRouter) -> None:
    """Register all 18 agents (6 types × 3 personalities)."""
    sandbox = SandboxManager()

    profiles = {
        "narcissism": NARCISSUS,
        "psychopathy": PSYCHOPATH,
        "mach": MACHIAVELLI,
    }

    agent_classes = [
        ReconAgent,
        ExploiterAgent,
        PostExploitAgent,
        EvaderAgent,
        ADSpecialistAgent,
        PrivescAgent,
        JailbreakAgent,
    ]

    for agent_cls in agent_classes:
        for persona_key, profile in profiles.items():
            agent = agent_cls(
                name=f"{agent_cls.__name__}_{persona_key}",
                personality=profile,
                ai_router=router,
                sandbox=sandbox,
            )
            registry.register(agent)


async def init_router() -> AIRouter:
    """Initialize AI router with providers config."""
    config = {}
    if _PROVIDERS_FILE.exists():
        try:
            config = json.loads(_PROVIDERS_FILE.read_text())
        except Exception:
            pass

    router = AIRouter(providers_config=config)
    try:
        await router.initialize()
    except Exception:
        pass
    return router


async def run_mission(objective: str, persona: str = "mach") -> dict:
    """Run a full Dark Triad mission: plan → execute → report."""
    start = time.monotonic()

    # Init
    router = await init_router()
    registry = AgentRegistry()
    bootstrap_agents(registry, router)
    sandbox = SandboxManager()

    # Create plan using MissionPlanner (LLM-powered)
    from navmax.dark_triad.mission_planner import MissionPlanner

    planner = MissionPlanner(router, registry, sandbox)
    plan = await planner.plan(
        objective=objective,
        personality=persona,
        constraints={"aggression": "strategic"},
    )

    bm = BattleManager(registry, sandbox)
    report = await bm.execute_plan(plan)

    duration = (time.monotonic() - start) * 1000
    return {
        "success": report.success,
        "completed": f"{report.phases_completed}/{report.phases_total}",
        "failed": report.phases_failed,
        "duration_ms": round(duration),
        "phases": [
            {
                "name": r.phase_id,
                "agent": r.agent_name,
                "status": r.status.value,
                "duration_ms": round(r.duration_ms),
                "output": r.output[:300] if r.output else "",
            }
            for r in report.phase_results
        ],
    }
