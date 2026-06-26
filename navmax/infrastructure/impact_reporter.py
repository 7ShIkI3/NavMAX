"""Infrastructure Impact Reporter — rapports d'impact business.

Combine les données AD, firewall, et vulnérabilités pour produire
des rapports qui expliquent l'IMPACT MÉTIER — pas juste la technique.

Usage:
    reporter = ImpactReporter(ai_engine=None)
    report = await reporter.generate(domain_map, fw_config, vuln_report)
    print(report)
"""

from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)


class ImpactLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class BusinessImpact:
    """Un impact métier identifié."""

    title: str
    description: str
    level: ImpactLevel
    affected_assets: list[str] = field(default_factory=list)
    financial_risk: str = ""  # "~500k€", "Non quantifiable"
    data_risk: str = ""  # "PII de 5000 clients", "Données financières"
    compliance_risk: str = ""  # "RGPD Article 32", "PCI-DSS 4.0"
    remediation_priority: int = 0  # 1 = immédiat, 2 = 48h, 3 = semaine


@dataclass
class ImpactReport:
    """Rapport d'impact métier complet."""

    title: str = "Infrastructure Security Impact Report"
    generated: str = ""
    overall_risk: ImpactLevel = ImpactLevel.LOW
    impacts: list[BusinessImpact] = field(default_factory=list)
    executive_summary: str = ""
    recommendations: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            "=" * 70,
            f"  {self.title}",
            f"  Overall Risk: {self.overall_risk.upper()}",
            "=" * 70,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 70,
            self.executive_summary,
            "",
        ]

        if self.impacts:
            lines.append("BUSINESS IMPACTS (prioritized)")
            lines.append("-" * 70)
            for impact in sorted(self.impacts, key=lambda i: i.remediation_priority):
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                    impact.level, "❓",
                )
                lines.append(f"\n{emoji} [{impact.level.upper()}] {impact.title}")
                lines.append(f"   {impact.description}")
                if impact.financial_risk:
                    lines.append(f"   Financial risk: {impact.financial_risk}")
                if impact.data_risk:
                    lines.append(f"   Data at risk: {impact.data_risk}")
                if impact.compliance_risk:
                    lines.append(f"   Compliance: {impact.compliance_risk}")
                if impact.affected_assets:
                    lines.append(f"   Affected: {', '.join(impact.affected_assets[:5])}")

        if self.recommendations:
            lines.append("\n\nTOP RECOMMENDATIONS")
            lines.append("-" * 70)
            for i, rec in enumerate(self.recommendations[:5], 1):
                lines.append(f"  {i}. {rec}")

        lines.append("\n" + "=" * 70)
        return "\n".join(lines)


class ImpactReporter:
    """Générateur de rapports d'impact métier.

    Corrèle les données techniques AD + Firewall + Vulnérabilités
    et produit un rapport orienté business.

    Usage:
        reporter = ImpactReporter()
        report = await reporter.generate(domain_map, fw_config, vuln_report)
    """

    def __init__(self, ai_engine=None) -> None:
        self.ai = ai_engine

    async def generate(
        self,
        domain_map=None,
        fw_config=None,
        vuln_report=None,
        attack_paths=None,
    ) -> ImpactReport:
        """Génère un rapport d'impact métier.

        Args:
            domain_map: DomainMap AD
            fw_config: FirewallConfig
            vuln_report: ScanReport vulnérabilités
            attack_paths: AttackPathAnalysis

        Returns:
            ImpactReport complet

        """
        import datetime

        report = ImpactReport(
            generated=datetime.datetime.now().isoformat(),
        )

        impacts: list[BusinessImpact] = []
        total_risk_score = 0

        # ── AD: Comptes admin Kerberoastable ──────────────────
        if domain_map:
            kerb_admin = [u for u in domain_map.kerberoastable_users if u.is_admin]
            if kerb_admin:
                impacts.append(
                    BusinessImpact(
                        title=f"{len(kerb_admin)} admin accounts are Kerberoastable",
                        description=(
                            "Service accounts with administrative privileges "
                            "have SPNs configured. An attacker can request a "
                            "Kerberos ticket, crack the hash offline, and gain "
                            "full domain admin access."
                        ),
                        level=ImpactLevel.CRITICAL,
                        affected_assets=[u.sam_account_name for u in kerb_admin],
                        financial_risk="Full domain compromise — ransomware potential",
                        data_risk="All domain data accessible",
                        compliance_risk="ISO 27001 A.9.2, NIST 800-53 AC-6",
                        remediation_priority=1,
                    ),
                )
                total_risk_score += 35

            # AD: Délégation non contrainte
            unconstrained = domain_map.unconstrained_delegation_computers
            if unconstrained:
                impacts.append(
                    BusinessImpact(
                        title=f"{len(unconstrained)} hosts with unconstrained delegation",
                        description=(
                            "An attacker compromising any of these hosts can "
                            "impersonate ANY user authenticating to them. "
                            "Combined with a coercion attack, this leads to "
                            "immediate domain compromise."
                        ),
                        level=ImpactLevel.HIGH,
                        affected_assets=[c.dns_hostname for c in unconstrained],
                        financial_risk="Lateral movement → ransomware spread",
                        data_risk="All data accessible via impersonation",
                        compliance_risk="NIST 800-53 AC-3, ISO 27001 A.9.1.2",
                        remediation_priority=1,
                    ),
                )
                total_risk_score += 25

            # AD: Trop d'admins
            if len(domain_map.privileged_users) > 10:
                impacts.append(
                    BusinessImpact(
                        title=f"{len(domain_map.privileged_users)} privileged accounts",
                        description=(
                            "Excessive number of privileged accounts increases "
                            "the attack surface. Each admin account is a potential "
                            "entry point for domain compromise."
                        ),
                        level=ImpactLevel.MEDIUM,
                        affected_assets=[
                            u.sam_account_name for u in domain_map.privileged_users[:5]
                        ],
                        financial_risk="Increased breach probability",
                        compliance_risk="Least privilege principle violation",
                        remediation_priority=2,
                    ),
                )
                total_risk_score += 15

        # ── Firewall: Règles Any/Any ───────────────────────────
        if fw_config:
            risky = [
                r
                for r in fw_config.allow_rules
                if not r.source_addresses
                or "any" in [a.lower().strip() for a in r.source_addresses]
            ]
            if len(risky) > 5:
                impacts.append(
                    BusinessImpact(
                        title=f"{len(risky)} overly permissive firewall rules",
                        description=(
                            "Firewall rules with 'any' source allow traffic "
                            "from the entire internet, dramatically expanding "
                            "the attack surface."
                        ),
                        level=ImpactLevel.HIGH,
                        affected_assets=[r.name for r in risky[:5]],
                        financial_risk="External attack surface expansion",
                        compliance_risk="PCI-DSS 1.2, ISO 27001 A.13.1",
                        remediation_priority=2,
                    ),
                )
                total_risk_score += 20

            # FW: CVEs critiques
            critical_cves = [
                c for c in fw_config.cve_checks if c.severity == "critical" and c.vulnerable
            ]
            if critical_cves:
                impacts.append(
                    BusinessImpact(
                        title=f"{len(critical_cves)} critical CVEs on {fw_config.hostname}",
                        description=(
                            f"The firewall {fw_config.model} running "
                            f"{fw_config.version} has {len(critical_cves)} "
                            f"unpatched critical vulnerabilities."
                        ),
                        level=ImpactLevel.CRITICAL,
                        affected_assets=[c.cve_id for c in critical_cves],
                        financial_risk="Firewall compromise → full network access",
                        compliance_risk="PCI-DSS 6.1, NIST 800-53 SI-2",
                        remediation_priority=1,
                    ),
                )
                total_risk_score += 40

        # ── Vulns AD: Kerberoasting ────────────────────────────
        if vuln_report:
            for f in vuln_report.findings:
                if f.severity == "critical":
                    impacts.append(
                        BusinessImpact(
                            title=f"AD Critical: {f.title}",
                            description=f.description,
                            level=ImpactLevel.CRITICAL,
                            affected_assets=f.affected_assets,
                            financial_risk="Domain compromise",
                            remediation_priority=1,
                        ),
                    )
                    total_risk_score += 30

        # ── Déterminer le niveau global ───────────────────────
        if total_risk_score >= 60:
            report.overall_risk = ImpactLevel.CRITICAL
        elif total_risk_score >= 30:
            report.overall_risk = ImpactLevel.HIGH
        elif total_risk_score >= 10:
            report.overall_risk = ImpactLevel.MEDIUM
        else:
            report.overall_risk = ImpactLevel.LOW

        report.impacts = impacts

        # ── Résumé exécutif ────────────────────────────────────
        report.executive_summary = self._build_executive_summary(
            report,
            domain_map,
            fw_config,
            vuln_report,
        )

        # ── Recommandations ───────────────────────────────────
        report.recommendations = self._build_recommendations(impacts)

        return report

    def _build_executive_summary(
        self,
        report,
        domain_map,
        fw_config,
        vuln_report,
    ) -> str:
        """Construit le résumé exécutif."""
        parts = []

        if domain_map:
            parts.append(
                f"The Active Directory domain contains "
                f"{len(domain_map.users)} users, "
                f"{len(domain_map.privileged_users)} privileged accounts, "
                f"and {len(domain_map.domain_controllers)} domain controllers.",
            )

        if fw_config:
            cvss = sum(c.cvss_score for c in fw_config.cve_checks if c.vulnerable)
            parts.append(
                f"The firewall {fw_config.hostname} ({fw_config.model}) "
                f"has {sum(1 for c in fw_config.cve_checks if c.vulnerable)} "
                f"unpatched vulnerabilities (cumulative CVSS: {cvss:.1f}).",
            )

        parts.append(
            f"Overall risk level: {report.overall_risk.upper()}. "
            f"{len(report.impacts)} business impacts identified.",
        )

        return " ".join(parts)

    def _build_recommendations(
        self,
        impacts: list[BusinessImpact],
    ) -> list[str]:
        """Construit la liste de recommandations priorisées."""
        recs = []
        for impact in sorted(impacts, key=lambda i: i.remediation_priority):
            priority_label = {1: "IMMEDIATE", 2: "WITHIN 48h", 3: "WITHIN 1 WEEK"}.get(
                impact.remediation_priority,
                "",
            )
            recs.append(f"[{priority_label}] {impact.title}")
        return recs
