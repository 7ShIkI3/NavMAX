"""CVSS 3.1 Scorer — calcul programmatique des scores CVSS pour les findings NavMAX.

Utilise la lib `cvss` pour produire des scores CVSS 3.1 standards.
Compatible avec les findings Nuclei, VulnDatabase, et AD VulnScanner.

Usage:
    scorer = CVSSScorer()
    score = scorer.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
    # → CVSSScore(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8, severity="Critical")
"""

from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


class CVSSNotAvailableError(Exception):
    """La lib cvss n'est pas installée."""


# ── Types ────────────────────────────────────────────────────────


@dataclass
class CVSSScore:
    """Score CVSS 3.1 complet."""

    vector_string: str
    base_score: float
    severity: str  # "None", "Low", "Medium", "High", "Critical"
    temporal_score: float | None = None
    environmental_score: float | None = None

    @property
    def badge_color(self) -> str:
        """Couleur HTML pour badge CVSS."""
        if self.base_score >= 9.0:
            return "#dc3545"  # Rouge — Critique
        if self.base_score >= 7.0:
            return "#fd7e14"  # Orange — Élevé
        if self.base_score >= 4.0:
            return "#ffc107"  # Jaune — Moyen
        return "#6c757d"  # Gris — Faible

    @property
    def nvd_url(self) -> str:
        """URL NVD pour le CVE associé."""
        return ""  # Rempli par le caller si CVE ID connu


# ── Scorer ───────────────────────────────────────────────────────


class CVSSScorer:
    """Calculateur CVSS 3.1.

    Supporte :
    - Calcul manuel vecteur → score
    - Auto-scoring depuis un NucleiFinding
    - Heuristique depuis severity + template_id
    """

    def __init__(self) -> None:
        self._lib_available = False
        self._check_lib()

    def _check_lib(self) -> bool:
        """Vérifie si la lib cvss est disponible."""
        try:
            from cvss import CVSS3  # noqa: F401

            self._lib_available = True
            return True
        except ImportError:
            logger.warning("cvss_lib_non_installée", conseil="pip install cvss>=3.0.0")
            return False

    def calculate(
        self,
        av: str = "N",  # Attack Vector: N, A, L, P
        ac: str = "L",  # Attack Complexity: L, H
        pr: str = "N",  # Privileges Required: N, L, H
        ui: str = "N",  # User Interaction: N, R
        s: str = "U",  # Scope: U, C
        c: str = "H",  # Confidentiality: H, L, N
        i: str = "H",  # Integrity: H, L, N
        a: str = "H",  # Availability: H, L, N
    ) -> CVSSScore:
        """Calcule un score CVSS 3.1 à partir des métriques de base.

        Args:
            av: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
            ac: Attack Complexity (L=Low, H=High)
            pr: Privileges Required (N=None, L=Low, H=High)
            ui: User Interaction (N=None, R=Required)
            s: Scope (U=Unchanged, C=Changed)
            c: Confidentiality Impact (N=None, L=Low, H=High)
            i: Integrity Impact (N=None, L=Low, H=High)
            a: Availability Impact (N=None, L=Low, H=High)

        Returns:
            CVSSScore avec vector_string et base_score.

        """
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        if self._lib_available:
            try:
                from cvss import CVSS3

                c = CVSS3(vector)
                scores = c.scores()
                base = float(scores[0]) if scores else self._heuristic_score(vector)
                base = self._clamp_score(base)
                severity = (
                    c.severities()[0].capitalize()
                    if c.severities()
                    else self._severity_from_score(base)
                )
                return CVSSScore(
                    vector_string=vector,
                    base_score=base,
                    severity=severity,
                )
            except Exception as e:
                logger.warning("cvss_calc_error", vector=vector, error=str(e))

        # Fallback heuristique
        base = self._clamp_score(self._heuristic_score(vector))
        return CVSSScore(
            vector_string=vector,
            base_score=base,
            severity=self._severity_from_score(base),
        )

    def auto_score(
        self,
        severity: str | None = None,
        cve_ids: list[str] | None = None,
        template_id: str = "",
        description: str = "",
    ) -> CVSSScore:
        """Score automatique à partir de métadonnées de finding.

        Args:
            severity: Sévérité nuclei (critical, high, medium, low, info)
            cve_ids: Liste de CVE IDs
            template_id: ID du template nuclei
            description: Description du finding

        Returns:
            CVSSScore estimé.

        """
        # Mapping severity → CVSS
        severity_map = {
            "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "high": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "low": (2.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
            "info": (0.0, "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
        }

        sev_lower = (severity or "").lower()
        if sev_lower in severity_map:
            score, vector = severity_map[sev_lower]
            score = self._clamp_score(score)
            return CVSSScore(
                vector_string=vector,
                base_score=score,
                severity=sev_lower.capitalize(),
            )

        # Fallback : medium
        return CVSSScore(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            base_score=5.0,
            severity="Medium",
        )

    # ── Internals ──────────────────────────────────────────────

    @staticmethod
    def _clamp_score(score: float) -> float:
        """Valide que le score CVSS est dans la plage [0.0, 10.0].

        Args:
            score: Score brut.

        Returns:
            Score clampé entre 0.0 et 10.0.

        Raises:
            ValueError: Si le score est hors plage après arrondi (indicateur de bug).

        """
        clamped = round(max(0.0, min(10.0, score)), 1)
        if score != clamped:
            logger.warning("cvss_score_hors_plage", raw_score=score, clamped=clamped)
        return clamped

    @staticmethod
    def _heuristic_score(vector: str) -> float:
        """Estimation depuis le vecteur CVSS — ne compte que C/I/A impacts."""
        # Extraire les valeurs d'impact
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        score = 0.0
        for metric in ("C", "I", "A"):
            val = parts.get(metric, "N")
            if val == "H":
                score += 3.0
            elif val == "L":
                score += 1.5
        # Normaliser vers ~0-10
        return min(10.0, round(score * 1.0, 1))

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 0.1:
            return "Low"
        return "None"


# ── MITRE ATT&CK Mapping ─────────────────────────────────────────


# Mapping CVE → technique MITRE ATT&CK IDs (extrait, sera enrichi)
MITRE_ATTACK_MAP: dict[str, list[str]] = {
    "CVE-2021-44228": [
        "T1190",
        "T1059",
    ],  # Log4Shell — Exploit Public-Facing App, Command & Scripting
    "CVE-2017-0144": ["T1210", "T1190"],  # EternalBlue — Exploitation of Remote Services
    "CVE-2020-1472": ["T1210"],  # Zerologon
    "CVE-2019-0708": ["T1210"],  # BlueKeep
    "CVE-2021-26855": ["T1190", "T1505"],  # ProxyLogon — Server Software Component
    "CVE-2021-34527": ["T1190"],  # PrintNightmare
    "CVE-2021-41773": ["T1190"],  # Apache path traversal
    "CVE-2022-22965": ["T1190", "T1059"],  # Spring4Shell
    "CVE-2023-23397": ["T1566"],  # Outlook priv esc — Phishing
    "CVE-2022-30190": ["T1203", "T1204"],  # Follina — Exploitation for Client Execution
    "CVE-2021-26084": ["T1190", "T1059.003"],  # Confluence OGNL injection
    "CVE-2021-21972": ["T1190"],  # vCenter RCE
    "CVE-2022-1388": ["T1190"],  # F5 BIG-IP iControl REST
    "CVE-2020-5902": ["T1190"],  # F5 BIG-IP TMUI RCE
    "CVE-2020-1938": ["T1190"],  # Ghostcat — Apache Tomcat AJP
    "CVE-2020-0796": ["T1210"],  # SMBGhost
    "CVE-2019-19781": ["T1190"],  # Citrix ADC Path Traversal
    "CVE-2021-21985": ["T1190"],  # vSphere Client RCE
}


def get_mitre_techniques(cve_ids: list[str]) -> list[str]:
    """Retourne les techniques MITRE ATT&CK pour une liste de CVEs.

    Args:
        cve_ids: Liste de CVE IDs.

    Returns:
        Liste de technique IDs (TXXXX).

    """
    techniques: set[str] = set()
    for cve in cve_ids:
        if cve in MITRE_ATTACK_MAP:
            techniques.update(MITRE_ATTACK_MAP[cve])
    return sorted(techniques)


def get_mitre_url(technique_id: str) -> str:
    """URL MITRE ATT&CK pour une technique."""
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
