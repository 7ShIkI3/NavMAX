"""
SARIF 2.1.0 Exporter — export des findings NavMAX au format SARIF standard.

Le format SARIF (Static Analysis Results Interchange Format) est le standard
industriel pour l'échange de résultats d'analyse de sécurité. Compatible avec
GitHub Code Scanning, Azure DevOps, GitLab, et tous les outils SARIF.

Usage:
    exporter = SARIFExporter()
    sarif_json = exporter.export(findings, scan_info)
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# ── Types ────────────────────────────────────────────────────────


@dataclass
class SARIFResult:
    """Un résultat dans un rapport SARIF."""

    rule_id: str
    level: str  # "error", "warning", "note", "none"
    message: str
    locations: list[dict]
    properties: dict = field(default_factory=dict)
    cve_ids: list[str] = field(default_factory=list)


# ── Exporter ─────────────────────────────────────────────────────


class SARIFExporter:
    """Exporteur SARIF 2.1.0.

    Génère un rapport conforme au standard SARIF à partir des findings NavMAX.
    """

    def __init__(self, tool_name: str = "NavMAX", tool_version: str = "0.4.1") -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version

    def export(
        self,
        findings: list[dict[str, Any]],
        scan_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Exporte les findings en SARIF 2.1.0.

        Args:
            findings: Liste de findings (dicts avec: cve_id, title, severity, host, description, ...)
            scan_info: Infos du scan (target, duration, profile, ...)

        Returns:
            Document SARIF JSON complet.
        """
        results: list[dict] = []

        for finding in findings:
            # Déterminer le niveau SARIF
            level = self._severity_to_sarif_level(finding.get("severity", "medium"))

            # Construire le message
            cve_id = finding.get("cve_id", finding.get("template_id", ""))
            title = finding.get("title", finding.get("name", "Vulnérabilité inconnue"))
            host = finding.get("host", scan_info.get("target", "") if scan_info else "")

            message_text = f"[{cve_id}] {title}"
            if finding.get("description"):
                message_text += f" — {finding['description'][:200]}"

            # Location
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": host,
                    },
                    "region": {
                        "snippet": {"text": title},
                    },
                }
            }

            # Properties
            properties = {
                "cve_ids": finding.get("cve_ids", [cve_id] if cve_id else []),
                "host": host,
                "matched_at": finding.get("matched_at", host),
                "cvss_score": finding.get("cvss_score"),
                "cvss_vector": finding.get("cvss_vector", ""),
            }

            # MITRE ATT&CK
            from navmax.reporting.cvss_scorer import get_mitre_techniques
            mitre_ids = get_mitre_techniques(properties["cve_ids"])
            if mitre_ids:
                properties["mitre_attack_techniques"] = mitre_ids

            results.append({
                "ruleId": cve_id or str(uuid.uuid4()),
                "ruleIndex": 0,
                "level": level,
                "message": {
                    "text": message_text,
                },
                "locations": [location],
                "properties": properties,
            })

        target = scan_info.get("target", "") if scan_info else ""

        doc: dict[str, Any] = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/7ShIkI3/NavMAX",
                            "rules": self._build_rules(findings),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "originalUriBaseIds": {
                        "TARGET": {
                            "uri": target,
                        }
                    },
                }
            ],
        }

        logger.info(
            "sarif_export",
            findings=len(results),
            target=target,
        )

        return doc

    def export_json(self, findings: list[dict], scan_info: dict | None = None) -> str:
        """Export SARIF en string JSON formatée.

        Returns:
            Chaîne JSON indentée.
        """
        doc = self.export(findings, scan_info)
        return json.dumps(doc, indent=2, ensure_ascii=False)

    # ── Internals ──────────────────────────────────────────────

    @staticmethod
    def _severity_to_sarif_level(severity: str) -> str:
        """Map NavMAX severity → SARIF level."""
        severity_lower = severity.lower()
        if severity_lower in ("critical", "high"):
            return "error"
        elif severity_lower == "medium":
            return "warning"
        elif severity_lower == "low":
            return "note"
        else:
            return "none"

    @staticmethod
    def _build_rules(findings: list[dict]) -> list[dict]:
        """Construit la liste des règles SARIF."""
        seen: set[str] = set()
        rules: list[dict] = []

        for f in findings:
            rule_id = f.get("cve_id", f.get("template_id", ""))
            if not rule_id or rule_id in seen:
                continue
            seen.add(rule_id)

            rules.append({
                "id": rule_id,
                "name": f.get("title", f.get("name", rule_id)),
                "shortDescription": {
                    "text": f.get("description", "")[:200],
                },
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{rule_id}"
                           if rule_id.startswith("CVE-") else "",
            })

        return rules
