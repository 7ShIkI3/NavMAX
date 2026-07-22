"""Dark Triad — Multi-Agent Red Team Architecture (ULTIMATE).

21 agents × 3 personnalités × comportements réels.
Orchestrateur IA suprême avec analyse stratégique LLM,
sous-agents dynamiques, adaptation temps réel.
"""

from navmax.dark_triad.personality import (
    AggressionLevel, MACHIAVELLI, NARCISSUS, PSYCHOPATH,
    PersonalityMode, PersonalityProfile,
)
from navmax.dark_triad.behavior import (
    PersonalityBehavior, NARCISSUS_BEHAVIOR, PSYCHOPATH_BEHAVIOR,
    MACHIAVELLI_BEHAVIOR, get_behavior,
)
from navmax.dark_triad.shared import MissionPhase, MissionPlan, PhaseResult, PhaseStatus
from navmax.dark_triad.registry import AgentRegistry
from navmax.dark_triad.battle_manager import BattleManager
from navmax.dark_triad.orchestrator_supreme import DarkTriadOrchestrator

__all__ = [
    "AgentRegistry", "AggressionLevel",
    "BattleManager", "DarkTriadOrchestrator",
    "MACHIAVELLI", "MACHIAVELLI_BEHAVIOR",
    "MissionPhase", "MissionPlan",
    "NARCISSUS", "NARCISSUS_BEHAVIOR",
    "PSYCHOPATH", "PSYCHOPATH_BEHAVIOR",
    "PersonalityBehavior", "PersonalityMode", "PersonalityProfile",
    "PhaseResult", "PhaseStatus",
    "get_behavior",
]
