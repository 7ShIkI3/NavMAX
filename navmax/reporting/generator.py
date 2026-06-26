"""AIReportGenerator — génération de rapports d'audit par IA.

Produit des rapports structurés (HTML, Markdown) à partir des résultats
de mission : synthèse exécutive, méthodologie, findings, recommandations.

L'IA génère le contenu, le module formate en HTML/MD propre.
"""

import html
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

# ── System Prompt ──────────────────────────────────────────────

REPORT_SYSTEM = """You are a cybersecurity report writer for NavMAX.
Generate professional penetration test reports in structured sections.

RULES:
1. Be concise and factual — no speculation
2. Use severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
3. Include CVEs when applicable
4. Provide actionable remediation for each finding
5. Output as structured JSON with sections: executive_summary, methodology,
   findings (array), recommendations (array)

JSON FORMAT:
{
  "executive_summary": "2-3 sentences overview",
  "methodology": "Brief description of approach",
  "findings": [
    {
      "title": "...",
      "severity": "HIGH",
      "cve": "CVE-XXXX-XXXXX",
      "description": "...",
      "affected": "host:port",
      "evidence": "...",
      "remediation": "..."
    }
  ],
  "recommendations": [
    {"priority": 1, "action": "...", "details": "..."}
  ]
}"""

# ── Data Models ────────────────────────────────────────────────


@dataclass
class ReportFinding:
    title: str
    severity: str
    description: str = ""
    cve: str | None = None
    affected: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class AuditReport:
    title: str
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    executive_summary: str = ""
    methodology: str = ""
    findings: list[ReportFinding] = field(default_factory=list)
    recommendations: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "HIGH")


# ── Generator ──────────────────────────────────────────────────


class AIReportGenerator:
    """Générateur de rapports d'audit piloté par IA.

    Usage:
        gen = AIReportGenerator(ai_engine)
        report = await gen.generate(mission_result)
        html = gen.to_html(report)
        md = gen.to_markdown(report)
    """

    def __init__(self, ai_engine) -> None:
        self.ai = ai_engine

    async def generate(self, mission_result) -> AuditReport:
        """Génère un rapport à partir d'un résultat de mission.

        Args:
            mission_result: MissionResult de MissionOrchestrator.execute()

        Returns:
            AuditReport structuré

        """
        from navmax.ai.providers.base import ModelTier

        # Collecter les données
        findings_raw = self._collect_findings(mission_result)
        stats = self._compute_stats(mission_result)

        if not findings_raw:
            # Pas de findings → rapport simple sans IA
            return AuditReport(
                title=f"Mission: {mission_result.objective[:80]}",
                executive_summary=f"Mission completed with {mission_result.phases_succeeded}/{mission_result.phases_executed} phases succeeded.",
                stats=stats,
            )

        # IA génère le contenu
        prompt = self._build_prompt(mission_result, findings_raw, stats)

        try:
            result = await self.ai.generate(
                prompt=prompt,
                tier=ModelTier.MEDIUM,
                system=REPORT_SYSTEM,
                temperature=0.3,
                max_tokens=4096,
                json_mode=True,
            )

            data = self._parse_json(result.text)
            return AuditReport(
                title=f"Pentest Report — {mission_result.objective[:80]}",
                executive_summary=data.get("executive_summary", ""),
                methodology=data.get("methodology", ""),
                findings=[
                    ReportFinding(
                        title=f.get("title", ""),
                        severity=f.get("severity", "INFO"),
                        description=f.get("description", ""),
                        cve=f.get("cve"),
                        affected=f.get("affected", ""),
                        evidence=f.get("evidence", ""),
                        remediation=f.get("remediation", ""),
                    )
                    for f in data.get("findings", [])
                ],
                recommendations=data.get("recommendations", []),
                stats=stats,
            )

        except Exception as e:
            logger.warning("report_ai_failed", error=str(e))
            return AuditReport(
                title=f"Mission Report: {mission_result.objective[:80]}",
                executive_summary=f"Automated report. {mission_result.phases_succeeded}/{mission_result.phases_executed} phases succeeded.",
                stats=stats,
            )

    def _collect_findings(self, mission_result) -> list[dict]:
        """Extrait les findings des résultats de phase."""
        findings = []
        for result in (mission_result.results or {}).values():
            if isinstance(result, dict):
                if "vulnerabilities" in result:
                    for v in result["vulnerabilities"]:
                        findings.append(
                            {
                                "title": v.get("description", v.get("cve", "Vulnerability")),
                                "severity": v.get("severity", "MEDIUM"),
                                "cve": v.get("cve"),
                                "affected": f"{result.get('host', '?')}:{result.get('port', '?')}",
                                "evidence": json.dumps(v)[:300],
                            },
                        )
                if "services" in result:
                    for s in result["services"]:
                        findings.append(
                            {
                                "title": f"Service discovered: {s.get('service', '?')} {s.get('version', '')}",
                                "severity": "INFO",
                                "affected": f"{result.get('host', '?')}:{s.get('port', '?')}",
                            },
                        )
        return findings

    def _compute_stats(self, mission_result) -> dict:
        return {
            "objective": mission_result.objective,
            "target": mission_result.target,
            "phases_executed": mission_result.phases_executed,
            "phases_succeeded": mission_result.phases_succeeded,
            "phases_failed": mission_result.phases_failed,
            "duration_seconds": round(mission_result.duration_seconds, 1),
        }

    def _build_prompt(self, mission_result, findings: list[dict], stats: dict) -> str:
        lines = [
            f"Mission: {mission_result.objective}",
            f"Target: {mission_result.target or 'N/A'}",
            f"Phases: {stats['phases_succeeded']}/{stats['phases_executed']} succeeded",
            f"Duration: {stats['duration_seconds']}s",
            "",
            "Findings:",
        ]
        for f in findings[:20]:
            lines.append(f"  - [{f.get('severity', '?')}] {f.get('title', '?')}")
            if f.get("cve"):
                lines.append(f"    CVE: {f['cve']}")
        return "\n".join(lines)

    def _parse_json(self, text: str) -> dict:
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        brace = text.find("{")
        if brace >= 0:
            depth = 0
            for i in range(brace, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        text = text[brace : i + 1]
                        break
        return json.loads(text)

    # ── Formats de sortie ──────────────────────────────────────

    def to_markdown(self, report: AuditReport) -> str:
        """Convertit le rapport en Markdown."""
        lines = [
            f"# {report.title}",
            "",
            f"**Generated:** {report.generated_at[:19]}",
            "",
            "## Executive Summary",
            "",
            report.executive_summary or "_No summary available._",
            "",
            "## Statistics",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Phases executed | {report.stats.get('phases_executed', 0)} |",
            f"| Phases succeeded | {report.stats.get('phases_succeeded', 0)} |",
            f"| Duration | {report.stats.get('duration_seconds', 0)}s |",
            f"| Critical findings | {report.critical_count} |",
            f"| High findings | {report.high_count} |",
            "",
        ]

        if report.findings:
            lines.append("## Findings")
            lines.append("")
            for f in report.findings:
                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                    "INFO": "🔵",
                }.get(f.severity.upper(), "⚪")
                lines.append(f"### {severity_icon} [{f.severity}] {f.title}")
                if f.cve:
                    lines.append(f"**CVE:** {f.cve}  ")
                if f.affected:
                    lines.append(f"**Affected:** {f.affected}  ")
                if f.description:
                    lines.append("")
                    lines.append(f.description)
                if f.evidence:
                    lines.append("")
                    lines.append(f"**Evidence:** `{f.evidence[:200]}`")
                if f.remediation:
                    lines.append("")
                    lines.append(f"**Remediation:** {f.remediation}")
                lines.append("")

        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for r in report.recommendations:
                lines.append(f"{r.get('priority', '?')}. **{r.get('action', '')}**")
                if r.get("details"):
                    lines.append(f"   {r['details']}")
                lines.append("")

        return "\n".join(lines)

    def to_html(self, report: AuditReport) -> str:
        """Convertit le rapport en HTML standalone."""
        severity_colors = {
            "CRITICAL": "#d32f2f",
            "HIGH": "#f57c00",
            "MEDIUM": "#fbc02d",
            "LOW": "#388e3c",
            "INFO": "#1976d2",
        }

        findings_html = ""
        for f in report.findings:
            color = severity_colors.get(f.severity.upper(), "#666")
            safe_severity = html.escape(f.severity or "")
            safe_title = html.escape(f.title or "")
            safe_cve = html.escape(f.cve or "") if f.cve else ""
            safe_affected = html.escape(f.affected or "") if f.affected else ""
            safe_description = html.escape(f.description or "") if f.description else ""
            safe_remediation = html.escape(f.remediation or "") if f.remediation else ""
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; margin: 1em 0; padding: 0.5em 1em; background: #fafafa;">
                <h3 style="color:{color}">[{safe_severity}] {safe_title}</h3>
                {f"<p><strong>CVE:</strong> {safe_cve}</p>" if safe_cve else ""}
                {f"<p><strong>Affected:</strong> {safe_affected}</p>" if safe_affected else ""}
                {f"<p>{safe_description}</p>" if safe_description else ""}
                {f"<p><strong>Remediation:</strong> {safe_remediation}</p>" if safe_remediation else ""}
            </div>"""

        safe_title_html = html.escape(report.title or "")
        safe_generated_at = html.escape(report.generated_at[:19])
        safe_summary = html.escape(report.executive_summary or "No summary.")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{safe_title_html}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; color: #333; }}
h1 {{ border-bottom: 2px solid #1976d2; padding-bottom: 0.3em; }}
.stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1em; }}
.stat {{ background: #f5f5f5; padding: 1em; border-radius: 4px; text-align: center; }}
.stat .value {{ font-size: 2em; font-weight: bold; color: #1976d2; }}
</style>
</head>
<body>
<h1>{safe_title_html}</h1>
<p>Generated: {safe_generated_at}</p>
<h2>Executive Summary</h2>
<p>{safe_summary}</p>
<h2>Statistics</h2>
<div class="stats">
<div class="stat"><div class="value">{report.stats.get("phases_executed", 0)}</div>Phases</div>
<div class="stat"><div class="value">{report.critical_count}</div>Critical</div>
<div class="stat"><div class="value">{report.high_count}</div>High</div>
</div>
<h2>Findings ({len(report.findings)})</h2>
{findings_html}
</body>
</html>"""

    @staticmethod
    def _validate_output_path(output_path: str) -> Path:
        """Valide et résout un chemin de sortie pour prévenir le path traversal.

        Args:
            output_path: Chemin de sortie fourni par l'utilisateur.

        Returns:
            Path résolu et validé.

        Raises:
            ValueError: Si le chemin contient '..' ou est invalide.

        """
        resolved = Path(output_path).resolve()
        if ".." in str(Path(output_path)):
            msg = f"Chemin de sortie invalide : {output_path}"
            raise ValueError(msg)
        return resolved

    def save_html(self, report: AuditReport, output_path: str) -> Path:
        """Sauvegarde le rapport en HTML.

        Args:
            report: Rapport à sauvegarder.
            output_path: Chemin du fichier de sortie.

        Returns:
            Path absolu du fichier créé.

        """
        path = self._validate_output_path(output_path)
        content = self.to_html(report)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("rapport_html_sauvegarde", path=str(path))
        return path

    def save_markdown(self, report: AuditReport, output_path: str) -> Path:
        """Sauvegarde le rapport en Markdown.

        Args:
            report: Rapport à sauvegarder.
            output_path: Chemin du fichier de sortie.

        Returns:
            Path absolu du fichier créé.

        """
        path = self._validate_output_path(output_path)
        content = self.to_markdown(report)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("rapport_md_sauvegarde", path=str(path))
        return path
