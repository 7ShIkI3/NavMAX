"""
Mission Planner — décomposition d'objectifs en langage naturel en phases exécutables.

Utilise l'AIEngine (tier MEDIUM) pour transformer un objectif comme
"Trouve la base de données sensible sur 10.0.0.0/24" en un plan structuré
avec dépendances entre phases.

Format de sortie: JSON avec phases ordonnancées.
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import structlog

from navmax.ai.engine import AIEngine
from navmax.ai.providers.base import ModelTier

logger = structlog.get_logger(__name__)

# ── System Prompts ─────────────────────────────────────────────

MISSION_PLANNER_SYSTEM = """You are NavMAX, an autonomous cybersecurity penetration testing agent.
Your ONLY role is to plan missions. You do NOT execute anything — you produce JSON plans.

You have access to these NavMAX modules:

MODULES AVAILABLE:
- scanner: TCP/SYN/UDP port scanning, service fingerprinting, OS detection, vulnerability scanning
- osint: DNS recon, WHOIS, SSL certificates, Shodan/Censys, subdomain enumeration, technology detection
- ad: Active Directory & LDAP enumeration — mass extraction of users, groups, computers,
  OUs, GPOs, domain trusts. Builds attack graphs (BloodHound-like), detects Kerberoastable/AS-REP
  roastable accounts, password spraying, delegation abuse, ADCS misconfigurations,
  privileged group analysis, and LDAP/S signing checks
- exploit: 24 exploit modules including SSH bruteforce, Redis unauth, MongoDB unauth,
  MySQL/Postgres bruteforce, SMB enumeration, Docker API exploit, Kubernetes anonymous access,
  Elasticsearch unauth, Jenkins script console, SNMP public community, and more
- proxy: MITM HTTPS proxy, web crawling, form detection, technology fingerprinting,
  directory busting, JSON/XML fuzzing, structural fuzzing
- sandbox: Docker-isolated code execution for safe payload testing

RULES:
1. Decompose the objective into sequential phases
2. Each phase uses ONE module
3. Phases can depend on previous phases (use depends_on with phase ids)
4. Start with reconnaissance (scanner + osint), then exploitation
5. Be specific about parameters (ports, service names, etc.)
6. Output ONLY valid JSON — no markdown, no explanations

JSON FORMAT:
{
  "phases": [
    {
      "id": "phase_1",
      "description": "Port scan the target to discover open services",
      "module_needed": "scanner",
      "parameters": {"target": "10.0.0.1", "ports": "1-1000"},
      "depends_on": []
    },
    {
      "id": "phase_2",
      "description": "Gather OSINT on the target domain",
      "module_needed": "osint",
      "parameters": {"target": "example.com"},
      "depends_on": []
    },
    {
      "id": "phase_3",
      "description": "Attempt exploitation based on discovered services",
      "module_needed": "exploit",
      "parameters": {"service_hint": "http"},
      "depends_on": ["phase_1"]
    }
  ]
}"""

MISSION_PLANNER_TEMPLATE = """Mission objective: {objective}

{facts_section}

Generate a detailed attack plan in JSON format. Each phase should be concrete and actionable.
Focus on the MOST LIKELY attack path — don't enumerate all possibilities."""


# ── Data Models ────────────────────────────────────────────────

class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class MissionPhase:
    """Une phase du plan de mission."""
    id: str
    description: str
    module_needed: str   # scanner, osint, exploit, proxy, sandbox
    parameters: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    status: PhaseStatus = PhaseStatus.PENDING
    result: Optional[dict] = None
    error: Optional[str] = None


@dataclass
class MissionPlan:
    """Plan de mission complet."""
    objective: str
    target: Optional[str] = None
    phases: list[MissionPhase] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def phase_count(self) -> int:
        return len(self.phases)

    @property
    def modules_used(self) -> list[str]:
        return list(set(p.module_needed for p in self.phases))

    def get_ready_phases(self) -> list[MissionPhase]:
        """Phases prêtes à être exécutées (dépendances satisfaites)."""
        completed = {p.id for p in self.phases if p.status == PhaseStatus.COMPLETED}
        return [
            p for p in self.phases
            if p.status == PhaseStatus.PENDING
            and all(dep in completed for dep in p.depends_on)
        ]

    def topological_order(self) -> list[MissionPhase]:
        """Ordonnancement topologique des phases."""
        ordered = []
        remaining = list(self.phases)
        completed = set()

        while remaining:
            ready = [
                p for p in remaining
                if all(dep in completed for dep in p.depends_on)
            ]
            if not ready:
                # Cycle ou dépendance manquante — prendre le reste
                ordered.extend(remaining)
                break
            next_phase = ready[0]
            ordered.append(next_phase)
            completed.add(next_phase.id)
            remaining.remove(next_phase)

        return ordered


# ── Planner ────────────────────────────────────────────────────

class MissionPlanner:
    """Planificateur de mission utilisant l'IA pour décomposer les objectifs.

    Usage:
        planner = MissionPlanner(engine)
        plan = await planner.plan("Trouve la BDD sensible sur 10.0.0.0/24", target="10.0.0.0/24")
        for phase in plan.topological_order():
            print(f"→ {phase.id}: {phase.description}")
    """

    def __init__(self, engine: AIEngine):
        self.engine = engine

    async def plan(self, objective: str, *,
                   target: Optional[str] = None,
                   known_services: Optional[list[dict]] = None,
                   known_vulns: Optional[list[str]] = None,
                   constraints: Optional[str] = None) -> MissionPlan:
        """Génère un plan de mission à partir d'un objectif en langage naturel.

        Args:
            objective: Description de la mission (ex: "Audite le réseau 10.0.0.0/24")
            target: Cible optionnelle (IP, domaine, CIDR)
            known_services: Services déjà découverts (pour enrichir le prompt)
            known_vulns: Vulnérabilités déjà connues
            constraints: Contraintes (ex: "pas de DoS", "heures ouvrées uniquement")

        Returns:
            MissionPlan avec les phases ordonnancées
        """
        # Construire le prompt enrichi
        facts = []
        if target:
            facts.append(f"Target: {target}")
        if known_services:
            svc_lines = [
                f"  - {s.get('host', '?')}:{s.get('port', '?')} {s.get('service', '?')}"
                for s in known_services[:10]
            ]
            facts.append(f"Already discovered services:\n" + "\n".join(svc_lines))
        if known_vulns:
            facts.append(f"Known vulnerabilities: {', '.join(known_vulns[:5])}")
        if constraints:
            facts.append(f"Constraints: {constraints}")

        facts_section = ""
        if facts:
            facts_section = "Known information:\n" + "\n".join(facts) + "\n"

        prompt = MISSION_PLANNER_TEMPLATE.format(
            objective=objective,
            facts_section=facts_section,
        )

        logger.info("planning_mission", objective=objective, target=target)

        # Générer le plan via l'IA (tier MEDIUM pour la planification)
        result = await self.engine.generate(
            prompt=prompt,
            tier=ModelTier.MEDIUM,
            system=MISSION_PLANNER_SYSTEM,
            temperature=0.3,        # basse température = plan cohérent
            max_tokens=4096,
            json_mode=True,
        )

        return self._parse_response(result.text, objective, target)

    def _parse_response(self, response: str, objective: str,
                        target: Optional[str]) -> MissionPlan:
        """Parse la réponse JSON de l'IA en MissionPlan.

        Gère les cas où l'IA wrappe le JSON dans du markdown.
        """
        json_str = self._extract_json(response)

        try:
            data = json.loads(json_str)
            phases = []
            for i, p in enumerate(data.get("phases", [])):
                phase = MissionPhase(
                    id=p.get("id", f"phase_{i+1}"),
                    description=p.get("description", f"Phase {i+1}"),
                    module_needed=p.get("module_needed", "scanner"),
                    parameters=p.get("parameters", {}),
                    depends_on=p.get("depends_on", []),
                )
                phases.append(phase)

            if not phases:
                raise ValueError("Empty phases list")

            return MissionPlan(
                objective=objective,
                target=target,
                phases=phases,
                metadata={
                    "raw_response": response,
                    "model": "ai-generated",
                }
            )
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.error("plan_parse_failed", error=str(e),
                          response_preview=response[:200])
            return self._fallback_plan(objective, target)

    def _extract_json(self, text: str) -> str:
        """Extrait le JSON d'une réponse potentiellement formatée en markdown."""
        text = text.strip()

        # ```json ... ```
        if "```json" in text:
            parts = text.split("```json", 1)[1].split("```", 1)
            return parts[0].strip()
        elif "```" in text:
            parts = text.split("```", 1)[1].split("```", 1)
            return parts[0].strip()

        # { ... } — find first JSON object even with prefix text
        first_brace = text.find("{")
        if first_brace >= 0:
            text = text[first_brace:]  # strip prefix text
            # Find matching closing brace
            depth = 0
            for i, c in enumerate(text):
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return text[:i+1]

        return text

    def _fallback_plan(self, objective: str,
                       target: Optional[str]) -> MissionPlan:
        """Plan par défaut quand l'IA échoue à produire du JSON valide."""
        logger.warning("using_fallback_plan", objective=objective)
        return MissionPlan(
            objective=objective,
            target=target,
            phases=[
                MissionPhase(
                    id="phase_1",
                    description=f"Port scan the target",
                    module_needed="scanner",
                    parameters={"target": target} if target else {},
                ),
                MissionPhase(
                    id="phase_2",
                    description="Gather OSINT intelligence",
                    module_needed="osint",
                    parameters={"target": target} if target else {},
                ),
                MissionPhase(
                    id="phase_3",
                    description="Analyze scan results and attempt exploitation",
                    module_needed="exploit",
                    parameters={},
                    depends_on=["phase_1", "phase_2"],
                ),
            ],
            metadata={"fallback": True},
        )
