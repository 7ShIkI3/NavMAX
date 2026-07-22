"""Dark Triad — Personality Behavior Engine.

Les 3 personnalités ne sont PAS cosmétiques. Chaque mode change
radicalement le comportement de TOUS les agents :
- Nombre de tentatives
- Parallélisme
- Furtivité vs agressivité
- Vérification post-action
- Niveau de bruit réseau
- Timeouts et délais
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BehaviorTrait(Enum):
    """Traits comportementaux qui affectent tous les agents."""
    AGGRESSION = "aggression"        # 0=stealth, 1=full send
    PARALLELISM = "parallelism"      # 0=sequential, 1=all at once
    VERIFICATION = "verification"    # 0=never check, 1=always double-check
    STEALTH = "stealth"              # 0=loud, 1=ghost
    PERSISTENCE = "persistence"      # 0=give up, 1=never stop
    NOISE_LEVEL = "noise_level"      # 0=silent, 1=maximum noise
    RETRY_COUNT = "retry_count"      # nombre de tentatives
    TIMEOUT_STYLE = "timeout_style"  # 0=impatient, 1=patient


@dataclass
class PersonalityBehavior:
    """Comportement complet dicté par la personnalité.

    Narcissus  : agressif, parallèle, jamais vérifie, bruyant, impatient
    Psychopath : tout en parallèle, force brute, zéro limite, maximum bruit
    Machiavelli: séquentiel, furtif, toujours vérifie, silencieux, patient
    """

    name: str
    emoji: str
    style: str

    # Traits numériques (0.0 à 1.0)
    aggression: float = 0.5
    parallelism: float = 0.5
    verification: float = 0.5
    stealth: float = 0.5
    persistence: float = 0.5
    noise_level: float = 0.5

    # Paramètres opérationnels
    max_parallel: int = 3
    retry_count: int = 1
    timeout_multiplier: float = 1.0
    delay_between_actions: float = 0.0  # secondes (furtivité)

    # Stratégies
    verify_after_action: bool = False
    cleanup_after_mission: bool = False
    spawn_sub_agents: bool = False
    use_stealth_exfil: bool = False
    aggressive_exploits: bool = False

    # Scan nmap
    nmap_speed: str = "T3"
    nmap_stealth: bool = False
    scan_all_ports: bool = False

    # Exploit
    exploit_parallel: bool = False
    exploit_verify: bool = False
    use_nuclei_full: bool = False

    def get_timeout(self, base: float) -> float:
        return base * self.timeout_multiplier

    def should_retry(self) -> bool:
        return self.retry_count > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "emoji": self.emoji, "style": self.style,
            "aggression": self.aggression, "parallelism": self.parallelism,
            "verification": self.verification, "stealth": self.stealth,
            "persistence": self.persistence, "noise_level": self.noise_level,
            "max_parallel": self.max_parallel, "retry_count": self.retry_count,
            "verify_after_action": self.verify_after_action,
            "cleanup_after_mission": self.cleanup_after_mission,
            "spawn_sub_agents": self.spawn_sub_agents,
            "use_stealth_exfil": self.use_stealth_exfil,
            "aggressive_exploits": self.aggressive_exploits,
        }


# ── Pre-built behaviors ──────────────────────────────────────────────────────

NARCISSUS_BEHAVIOR = PersonalityBehavior(
    name="Narcissus",
    emoji="🪞",
    style="Blitzkrieg — tout, tout de suite, aucune vérification, confiance absolue",
    aggression=0.9, parallelism=0.9, verification=0.0,
    stealth=0.1, persistence=0.3, noise_level=0.9,
    max_parallel=10, retry_count=0, timeout_multiplier=0.5,
    delay_between_actions=0.0,
    verify_after_action=False, cleanup_after_mission=False,
    spawn_sub_agents=True, use_stealth_exfil=False,
    aggressive_exploits=True,
    nmap_speed="T5", nmap_stealth=False, scan_all_ports=True,
    exploit_parallel=True, exploit_verify=False, use_nuclei_full=False,
)

PSYCHOPATH_BEHAVIOR = PersonalityBehavior(
    name="Psychopath",
    emoji="🔪",
    style="Apocalypse — force brute, parallélisme maximal, zéro limite, tout essayer",
    aggression=1.0, parallelism=1.0, verification=0.0,
    stealth=0.0, persistence=1.0, noise_level=1.0,
    max_parallel=50, retry_count=999, timeout_multiplier=2.0,
    delay_between_actions=0.0,
    verify_after_action=False, cleanup_after_mission=False,
    spawn_sub_agents=True, use_stealth_exfil=False,
    aggressive_exploits=True,
    nmap_speed="T5", nmap_stealth=False, scan_all_ports=True,
    exploit_parallel=True, exploit_verify=False, use_nuclei_full=True,
)

MACHIAVELLI_BEHAVIOR = PersonalityBehavior(
    name="Machiavelli",
    emoji="🕸️",
    style="Ghost — furtif, méthodique, patient, toujours vérifier, jamais détecté",
    aggression=0.2, parallelism=0.3, verification=1.0,
    stealth=0.95, persistence=0.8, noise_level=0.05,
    max_parallel=3, retry_count=0, timeout_multiplier=3.0,
    delay_between_actions=2.0,
    verify_after_action=True, cleanup_after_mission=True,
    spawn_sub_agents=False, use_stealth_exfil=True,
    aggressive_exploits=False,
    nmap_speed="T2", nmap_stealth=True, scan_all_ports=False,
    exploit_parallel=False, exploit_verify=True, use_nuclei_full=False,
)

# ── Behavior resolver ──────────────────────────────────────────────────────

_BEHAVIOR_MAP = {
    "narcissism": NARCISSUS_BEHAVIOR,
    "psychopathy": PSYCHOPATH_BEHAVIOR,
    "mach": MACHIAVELLI_BEHAVIOR,
    "machiavellianism": MACHIAVELLI_BEHAVIOR,
}


def get_behavior(persona: str) -> PersonalityBehavior:
    """Retourne le comportement correspondant à la personnalité."""
    return _BEHAVIOR_MAP.get(persona.lower(), MACHIAVELLI_BEHAVIOR)
