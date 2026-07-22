#!/usr/bin/env python3
"""
Dark Triad — Orchestrateur Trinitaire + Cyber Kill Chain Engine v3.0

L'agent principal UNIFIÉ a les 3 personnalités fusionnées.
Il sélectionne le mode automatiquement selon la phase.
Il délègue les tâches aux sous-agents via une Cyber Kill Chain.
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Cyber Kill Chain ───────────────────────────────────────────────────────

class KillChainPhase(Enum):
    RECON = "reconnaissance"
    WEAPONIZE = "weaponization"
    DELIVER = "delivery"
    EXPLOIT = "exploitation"
    INSTALL = "installation"
    C2 = "command_and_control"
    ACTIONS = "actions_on_objective"


# Mapping phases → agents + personnalité recommandée
PHASE_AGENT_MAP = {
    KillChainPhase.RECON: {
        "agents": ["ReconAgent"],
        "persona": "mach",  # Stratégique
        "emoji": "🔍",
        "color": "#f59e0b",  # ambre
        "description": "Cartographie de la surface d'attaque",
        "tool": "scan_ports",
    },
    KillChainPhase.WEAPONIZE: {
        "agents": ["ExploiterAgent", "JailbreakAgent"],
        "persona": "mach",
        "emoji": "⚔️",
        "color": "#f97316",  # orange
        "description": "Préparation des exploits et payloads",
        "tool": "nuclei_scan",
    },
    KillChainPhase.DELIVER: {
        "agents": ["ExploiterAgent"],
        "persona": "narcissism",  # Agressif
        "emoji": "📨",
        "color": "#ef4444",  # rouge
        "description": "Livraison des payloads à la cible",
        "tool": "exec_cmd",
    },
    KillChainPhase.EXPLOIT: {
        "agents": ["ExploiterAgent", "PrivescAgent"],
        "persona": "narcissism",
        "emoji": "💥",
        "color": "#dc2626",
        "description": "Exploitation des vulnérabilités",
        "tool": "full_audit",
    },
    KillChainPhase.INSTALL: {
        "agents": ["PostExploitAgent"],
        "persona": "psychopathy",  # Sans limites
        "emoji": "📥",
        "color": "#7c3aed",  # violet
        "description": "Installation de persistence et backdoors",
        "tool": "privesc_check",
    },
    KillChainPhase.C2: {
        "agents": ["PostExploitAgent", "EvaderAgent"],
        "persona": "psychopathy",
        "emoji": "🕸️",
        "color": "#4f46e5",
        "description": "Établissement du canal de commande et contrôle",
        "tool": "exec_cmd",
    },
    KillChainPhase.ACTIONS: {
        "agents": ["PrivescAgent", "JailbreakAgent", "ADSpecialistAgent"],
        "persona": "psychopathy",
        "emoji": "🏁",
        "color": "#0891b2",  # cyan
        "description": "Objectifs finaux : exfiltration, DA, flag",
        "tool": "full_audit",
    },
}

KILL_CHAIN_ORDER = list(KillChainPhase)


# ── Question Templates ─────────────────────────────────────────────────────

@dataclass
class Question:
    id: str
    text: str
    phase: KillChainPhase
    choices: list[str] = field(default_factory=list)
    multi_select: bool = False
    required: bool = True
    example: str = ""


# Questions progressives — de générales à ultra-spécifiques
QUESTION_TREE = [
    # Phase 1: Target basics
    Question(
        id="target", text="🎯 Quelle est la cible exacte ?",
        phase=KillChainPhase.RECON,
        choices=["Adresse IP unique", "Réseau /24", "Domaine web", "Plage d'IPs custom"],
        example="ex: 10.0.0.1, 192.168.1.0/24, app.example.com",
    ),
    Question(
        id="target_count", text="Combien d'hôtes env. dans le scope ?",
        phase=KillChainPhase.RECON,
        choices=["1 seul", "2-10", "11-50", "50+"],
    ),
    Question(
        id="environment", text="🏢 Quel est l'environnement ?",
        phase=KillChainPhase.RECON,
        choices=["Cloud (AWS/GCP/Azure)", "On-premise (réseau local)", "Hybride", "Je ne sais pas"],
    ),
    # Phase 2: Audit scope
    Question(
        id="audit_type", text="🔬 Quel type d'audit souhaites-tu ?",
        phase=KillChainPhase.WEAPONIZE,
        choices=["Web Application", "Réseau interne", "Active Directory", "API / Microservices",
                 "Infrastructure Cloud", "Full Stack (tout)"],
    ),
    Question(
        id="credentials", text="🔑 Disposes-tu de credentials ?",
        phase=KillChainPhase.WEAPONIZE,
        choices=["Admin / root", "Utilisateur standard", "Aucun", "Token / Cookie de session"],
    ),
    Question(
        id="stealth_level", text="🥷 Quel niveau de furtivité ?",
        phase=KillChainPhase.WEAPONIZE,
        choices=["Stealth ++ (T1, slow, clean)", "Stealth (T2, normal)", 
                 "Équilibré (T4)", "Agressif (T5, tous les outils)", "Paranoïaque (T1, low&slow)"],
    ),
    # Phase 3: Attack specific
    Question(
        id="critical_assets", text="💎 Quels sont les assets critiques à cibler ?",
        phase=KillChainPhase.DELIVER,
        choices=["Base de données", "Contrôleur de domaine (DC)", "Serveurs web",
                 "API endpoints", "Infra DevOps (CI/CD)", "Je ne sais pas — découvre-les"],
        multi_select=True,
    ),
    Question(
        id="known_vulns", text="⚠️ Des vulnérabilités connues sur la cible ?",
        phase=KillChainPhase.DELIVER,
        choices=["Oui, j'ai une liste", "Non, aucune idée", "Juste des suppositions"],
    ),
    Question(
        id="waf_present", text="🛡️ La cible a-t-elle un WAF / IDS ?",
        phase=KillChainPhase.DELIVER,
        choices=["Oui (Cloudflare, AWS WAF...)", "Non", "Je ne sais pas"],
    ),
    # Phase 4: Exploitation details
    Question(
        id="exploit_prefs", text="💣 Préférences d'exploitation ?",
        phase=KillChainPhase.EXPLOIT,
        choices=["CVE connues uniquement", "Bruteforce autorisé", 
                 "Social engineering inclus", "Tout est permis", "CTF rules (pas de DoS)"],
    ),
    Question(
        id="pivot_needed", text="🔗 Faut-il pivoter après l'accès initial ?",
        phase=KillChainPhase.EXPLOIT,
        choices=["Oui, réseau interne à cartographier", "Non, un seul hôte suffit", "Peut-être, on verra"],
    ),
    # Phase 5: Post-exploitation
    Question(
        id="persistence", text="📌 Faut-il installer de la persistence ?",
        phase=KillChainPhase.INSTALL,
        choices=["Oui, backdoor discrète", "Non, smash & grab", "Juste un accès SSH persistant"],
    ),
    Question(
        id="exfil_method", text="📤 Méthode d'exfiltration préférée ?",
        phase=KillChainPhase.INSTALL,
        choices=["DNS tunneling", "HTTPS (port 443)", "SSH/SCP", "WebSocket", "Cloud storage (S3/GDrive)"],
    ),
    # Phase 6: Final objectives
    Question(
        id="end_goal", text="🏁 Objectif final de la mission ?",
        phase=KillChainPhase.ACTIONS,
        choices=["Flag / CTF", "Domain Admin (DA)", "Exfiltration de données",
                 "Défacement", "Preuve d'accès (screenshot)", "Rapport complet"],
    ),
    Question(
        id="time_limit", text="⏱ Contrainte de temps pour la mission ?",
        phase=KillChainPhase.ACTIONS,
        choices=["Aucune limite", "< 1 heure", "< 4 heures", "< 24 heures", "Fenêtre : nuit uniquement"],
    ),
]


# ── Node Visual (pour le graphe) ───────────────────────────────────────────

@dataclass
class KillChainNode:
    id: str
    phase: KillChainPhase
    agent_name: str
    status: str = "pending"  # pending | active | success | failed
    started_at: float = 0.0
    completed_at: float = 0.0
    result_summary: str = ""
    tool: str = ""
    delegated_from: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "phase": self.phase.value,
            "phase_emoji": PHASE_AGENT_MAP[self.phase]["emoji"],
            "agent": self.agent_name,
            "status": self.status,
            "color": PHASE_AGENT_MAP[self.phase]["color"],
            "tool": self.tool or PHASE_AGENT_MAP[self.phase]["tool"],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result_summary[:100],
            "delegated_from": self.delegated_from,
        }


# ── Mission State ──────────────────────────────────────────────────────────

@dataclass
class MissionState:
    mission_id: str
    target: str = ""
    current_phase_index: int = 0
    active_persona: str = "mach"
    nodes: list[KillChainNode] = field(default_factory=list)
    answers: dict = field(default_factory=dict)
    current_question_index: int = 0
    phase_statuses: dict = field(default_factory=lambda: {p: "pending" for p in KILL_CHAIN_ORDER})
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    findings: list = field(default_factory=list)
    conversation: list = field(default_factory=list)

    @property
    def current_phase(self) -> KillChainPhase:
        if self.current_phase_index >= len(KILL_CHAIN_ORDER):
            return KILL_CHAIN_ORDER[-1]
        return KILL_CHAIN_ORDER[self.current_phase_index]

    @property
    def progress_pct(self) -> float:
        done = sum(1 for s in self.phase_statuses.values() if s in ("success", "failed"))
        return (done / len(KILL_CHAIN_ORDER)) * 100

    def to_dict(self) -> dict:
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "current_phase": self.current_phase.value,
            "current_phase_index": self.current_phase_index,
            "active_persona": self.active_persona,
            "progress_pct": self.progress_pct,
            "phase_statuses": {k.value: v for k, v in self.phase_statuses.items()},
            "nodes": [n.to_dict() for n in self.nodes],
            "answers": self.answers,
            "current_question_index": self.current_question_index,
            "total_questions": len(QUESTION_TREE),
            "findings_count": len(self.findings),
            "elapsed_seconds": int(time.time() - self.started_at),
        }


# ── Missions actives ────────────────────────────────────────────────────────

_missions: dict[str, MissionState] = {}


def get_mission(mission_id: str) -> MissionState:
    if mission_id not in _missions:
        _missions[mission_id] = MissionState(mission_id=mission_id)
    return _missions[mission_id]
