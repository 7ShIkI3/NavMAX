"""Dark Triad — Personality Detector Engine.

Vrai calculateur de personnalité basé sur :
- Analyse sémantique multi-dimensionnelle
- Scoring d'agressivité, furtivité, urgence, violence, stratégie
- Patterns de langage (impératifs, conditionnels, menaces)
- Hystérésis pour éviter les changements trop rapides
- LLM fallback pour les cas ambigus (si l'IA est dispo)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PersonalityMode(Enum):
    MACHIAVELLI = "mach"
    NARCISSUS = "narcissism"
    PSYCHOPATH = "psychopathy"


@dataclass
class PersonalityScore:
    """Score multi-dimensionnel pour une personnalité."""
    mode: PersonalityMode
    aggression: float = 0.0     # 0.0-1.0 : force de frappe
    stealth: float = 0.0        # 0.0-1.0 : furtivité
    urgency: float = 0.0        # 0.0-1.0 : rapidité exigée
    brutality: float = 0.0      # 0.0-1.0 : violence/sans limites
    strategy: float = 0.0       # 0.0-1.0 : réflexion/planification
    confidence: float = 0.0     # 0.0-1.0 : certitude du scoring
    total: float = 0.0          # score pondéré final

    def weighted_score(self) -> float:
        """Score pondéré selon des poids calibrés."""
        weights = {
            PersonalityMode.MACHIAVELLI: {
                "stealth": 0.40, "strategy": 0.35, "aggression": -0.15, "urgency": 0.10,
            },
            PersonalityMode.NARCISSUS: {
                "aggression": 0.40, "confidence": 0.25, "urgency": 0.25, "strategy": -0.10,
            },
            PersonalityMode.PSYCHOPATH: {
                "brutality": 0.45, "aggression": 0.35, "urgency": 0.25,
                "stealth": -0.30, "strategy": -0.20,
            },
        }
        w = weights.get(self.mode, {})
        return (
            w.get("stealth", 0) * self.stealth +
            w.get("strategy", 0) * self.strategy +
            w.get("aggression", 0) * self.aggression +
            w.get("urgency", 0) * self.urgency +
            w.get("brutality", 0) * self.brutality +
            w.get("confidence", 0) * self.confidence
        )


# ── Patterns de détection (regex sémantiques) ────────────────────────────────

@dataclass
class SemanticPattern:
    pattern: re.Pattern
    weight: float  # -1.0 à 1.0
    dimension: str  # aggression, stealth, urgency, brutality, strategy


PATTERNS: list[SemanticPattern] = [
    # ═══ AGRESSION ═══
    SemanticPattern(re.compile(r'\b(fonce|attaque|frappe|cogne|explose|défonce)\b', re.I), 0.8, "aggression"),
    SemanticPattern(re.compile(r'\b(vite|rapide|immédiat|direct|maintenant|urgent)\b', re.I), 0.5, "aggression"),
    SemanticPattern(re.compile(r'\b(max|maximum|fond|pleine puissance|full)\b', re.I), 0.6, "aggression"),
    SemanticPattern(re.compile(r'\b(doucement|calme|tranquille|slow|posé)\b', re.I), -0.6, "aggression"),

    # ═══ FURTIVITÉ ═══
    SemanticPattern(re.compile(r'\b(furtif|discret|invisible|ghost|silencieux|stealth)\b', re.I), 0.9, "stealth"),
    SemanticPattern(re.compile(r'\b(caché|couvre|efface|gomme|nettoie|trace)\b', re.I), 0.7, "stealth"),
    SemanticPattern(re.compile(r'\b(lent|patience|méthodique|progressif)\b', re.I), 0.5, "stealth"),
    SemanticPattern(re.compile(r'\b(bruyant|loud|visible|ouvert|explicite)\b', re.I), -0.8, "stealth"),
    SemanticPattern(re.compile(r'\b(audit|scan|analyse|vérifie|check|inspecte)\b', re.I), 0.4, "stealth"),

    # ═══ URGENCE ═══
    SemanticPattern(re.compile(r'\b(urgent|vite|maintenant|tout de suite|immédiatement|go)\b', re.I), 0.9, "urgency"),
    SemanticPattern(re.compile(r'\b(dépêche|grouille|pressé|rapidos|asap)\b', re.I), 0.8, "urgency"),
    SemanticPattern(re.compile(r'\b(calme|tranquille|prends ton temps|pas pressé)\b', re.I), -0.7, "urgency"),
    SemanticPattern(re.compile(r'!{2,}', re.I), 0.4, "urgency"),  # Points d'exclamation multiples
    SemanticPattern(re.compile(r'\b(MAINTENANT|VITE|GO|NOW)\b'), 0.95, "urgency"),  # CAPS = urgence maximale

    # ═══ BRUTALITÉ ═══
    SemanticPattern(re.compile(r'\b(détrui[st]?|massacr|annihil|extermin|ravag|dévast)\b', re.I), 0.95, "brutality"),
    SemanticPattern(re.compile(r'\b(nuke|crash|smash|wreck|obliterate)\b', re.I), 0.9, "brutality"),
    SemanticPattern(re.compile(r'\b(tout cass|sans piti|no mercy|no limit|zéro limit)\b', re.I), 0.85, "brutality"),
    SemanticPattern(re.compile(r'\b(mort|tuer|kill|dead|rip|die)\b', re.I), 0.8, "brutality"),
    SemanticPattern(re.compile(r'\b(force brute|chaos|apocalypse|carnage)\b', re.I), 0.95, "brutality"),
    SemanticPattern(re.compile(r'\b(doux|gentil|safe|sécurisé|protégé|prudent)\b', re.I), -0.7, "brutality"),

    # ═══ STRATÉGIE ═══
    SemanticPattern(re.compile(r'\b(stratég|plan|réfléch|analys|étud|prépare?)\b', re.I), 0.8, "strategy"),
    SemanticPattern(re.compile(r'\b(méthod|séquentiel|étape|phase|process)\b', re.I), 0.7, "strategy"),
    SemanticPattern(re.compile(r'\b(optim|efficace|minimal|précis|chirurgical)\b', re.I), 0.5, "strategy"),
    SemanticPattern(re.compile(r'\b(improvis|aléatoir|random|n\'importe)\b', re.I), -0.8, "strategy"),
    SemanticPattern(re.compile(r'\b(audit|pentest|red team|test d\'intrusion)\b', re.I), 0.6, "strategy"),

    # ═══ QUESTIONS (indique réflexion stratégique) ═══
    SemanticPattern(re.compile(r'\?$'), 0.3, "strategy"),
    SemanticPattern(re.compile(r'\b(quel|quelle|quels|comment|pourquoi|peux-tu|peut-on)\b', re.I), 0.3, "strategy"),

    # ═══ IMPÉRATIFS (indique autorité/agression) ═══
    SemanticPattern(re.compile(r'^(fais|lance|exécute|attaque|scanne|casse|pète|trouve|donne)\b', re.I), 0.5, "aggression"),
    SemanticPattern(re.compile(r'^(va|vas-y|allez|go|let\'s)\b', re.I), 0.4, "aggression"),
]


class PersonalityDetector:
    """Détecteur de personnalité avec scoring multi-dimensionnel et hystérésis."""

    def __init__(self):
        self._current_mode: PersonalityMode = PersonalityMode.MACHIAVELLI
        self._previous_scores: dict[PersonalityMode, float] = {
            m: 0.0 for m in PersonalityMode
        }
        self._last_change_time: float = 0.0
        self._message_count: int = 0
        self._mode_history: list[tuple[float, PersonalityMode]] = []

        # Seuils de basculement (hystérésis)
        self.SWITCH_THRESHOLD: float = 0.15  # différence minimale pour changer
        self.MIN_MESSAGES_BEFORE_SWITCH: int = 1  # nb messages avant d'autoriser un switch
        self.COOLDOWN_SECONDS: float = 3.0  # délai minimum entre deux changements

    def detect(self, message: str) -> PersonalityMode:
        """Analyse un message et retourne la personnalité optimale."""
        self._message_count += 1

        # Calculer les scores pour chaque personnalité
        scores = self._compute_scores(message)

        # Déterminer le gagnant
        best_mode = max(scores, key=lambda m: scores[m].weighted_score())
        best_score = scores[best_mode].weighted_score()

        # Hystérésis : ne changer que si la différence est significative
        current_score = self._previous_scores.get(self._current_mode, 0.0)
        diff = best_score - current_score

        now = time.time()
        cooldown_ok = (now - self._last_change_time) > self.COOLDOWN_SECONDS

        if (best_mode != self._current_mode and
                diff > self.SWITCH_THRESHOLD and
                self._message_count >= self.MIN_MESSAGES_BEFORE_SWITCH and
                cooldown_ok):

            # Vérifier que le nouveau mode est stable (2 messages consécutifs)
            self._mode_history.append((now, best_mode))
            if len(self._mode_history) >= 2:
                last_two = self._mode_history[-2:]
                if last_two[0][1] == last_two[1][1]:
                    self._current_mode = best_mode
                    self._last_change_time = now

        # Mettre à jour les scores précédents
        self._previous_scores = {m: s.weighted_score() for m, s in scores.items()}

        return self._current_mode

    def _compute_scores(self, message: str) -> dict[PersonalityMode, PersonalityScore]:
        """Calcule les scores multi-dimensionnels pour chaque personnalité."""
        # Initialiser les scores à zéro
        raw: dict[str, float] = {
            "aggression": 0.0, "stealth": 0.0, "urgency": 0.0,
            "brutality": 0.0, "strategy": 0.0,
        }

        # Compter les hits de chaque pattern
        hit_counts: dict[str, int] = {k: 0 for k in raw}

        for sp in PATTERNS:
            matches = len(sp.pattern.findall(message))
            if matches > 0:
                raw[sp.dimension] += sp.weight * min(matches, 3)  # cap à 3 matches
                hit_counts[sp.dimension] += matches

        # Normaliser chaque dimension entre 0 et 1
        for dim in raw:
            raw[dim] = max(0.0, min(1.0, raw[dim] / max(1, hit_counts.get(dim, 1))))

        # Facteur de confiance : plus y'a de patterns matchés, plus on est confiant
        total_hits = sum(hit_counts.values())
        confidence = min(1.0, total_hits / 8.0)  # 8 hits = 100% confiance

        # Facteurs contextuels
        msg_len = len(message)
        caps_ratio = sum(1 for c in message if c.isupper()) / max(1, msg_len)

        # Beaucoup de majuscules → agressivité + urgence
        if caps_ratio > 0.4:
            raw["aggression"] = min(1.0, raw["aggression"] + 0.3)
            raw["urgency"] = min(1.0, raw["urgency"] + 0.2)

        # Messages très courts → urgence
        if msg_len < 20:
            raw["urgency"] = min(1.0, raw["urgency"] + 0.15)

        # Messages longs → stratégie
        if msg_len > 200:
            raw["strategy"] = min(1.0, raw["strategy"] + 0.25)

        # Construire les scores par personnalité
        return {
            PersonalityMode.MACHIAVELLI: PersonalityScore(
                mode=PersonalityMode.MACHIAVELLI,
                aggression=raw["aggression"] * 0.2,
                stealth=raw["stealth"] * 1.5,
                urgency=raw["urgency"] * 0.3,
                brutality=raw["brutality"] * 0.0,
                strategy=raw["strategy"] * 1.5,
                confidence=confidence,
                total=0.0,
            ),
            PersonalityMode.NARCISSUS: PersonalityScore(
                mode=PersonalityMode.NARCISSUS,
                aggression=raw["aggression"] * 1.5,
                stealth=raw["stealth"] * 0.1,
                urgency=raw["urgency"] * 1.2,
                brutality=raw["brutality"] * 0.3,
                strategy=raw["strategy"] * 0.3,
                confidence=confidence,
                total=0.0,
            ),
            PersonalityMode.PSYCHOPATH: PersonalityScore(
                mode=PersonalityMode.PSYCHOPATH,
                aggression=raw["aggression"] * 1.0,
                stealth=raw["stealth"] * 0.0,
                urgency=raw["urgency"] * 1.0,
                brutality=raw["brutality"] * 1.8,
                strategy=raw["strategy"] * 0.0,
                confidence=confidence,
                total=0.0,
            ),
        }

    def force_mode(self, mode: PersonalityMode) -> None:
        """Force un changement de personnalité (override manuel ou IA)."""
        self._current_mode = mode
        self._last_change_time = time.time()
        self._mode_history = []

    def get_stats(self) -> dict[str, Any]:
        """Retourne les statistiques du détecteur."""
        return {
            "current_mode": self._current_mode.value,
            "messages_analyzed": self._message_count,
            "last_change": self._last_change_time,
            "switch_threshold": self.SWITCH_THRESHOLD,
            "cooldown": self.COOLDOWN_SECONDS,
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_detector: PersonalityDetector | None = None


def get_detector() -> PersonalityDetector:
    global _detector
    if _detector is None:
        _detector = PersonalityDetector()
    return _detector
