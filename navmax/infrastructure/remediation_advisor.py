"""Remediation Advisor — suggestions de correctifs précises et actionnables.

Génère des recommandations de remédiation concrètes basées sur :
- Les vulnérabilités AD détectées
- Les anomalies de règles firewall
- Les chemins d'attaque critiques
- L'impact business

Usage:
    advisor = RemediationAdvisor()
    plan = advisor.build_remediation_plan(vuln_report, rule_analysis, attack_paths)
    for action in plan.actions:
        print(f"[{action.priority}] {action.command}")
"""

from dataclasses import dataclass, field
from enum import StrEnum

import structlog

logger = structlog.get_logger(__name__)


class ActionType(StrEnum):
    POWERSHELL = "powershell"
    CLI = "cli"
    GPO = "gpo"
    CONFIG = "config"
    MANUAL = "manual"
    API = "api"


class Priority(StrEnum):
    IMMEDIATE = "immediate"  # < 24h
    SHORT_TERM = "short_term"  # < 1 semaine
    MEDIUM_TERM = "medium_term"  # < 1 mois
    LONG_TERM = "long_term"  # > 1 mois


@dataclass
class RemediationAction:
    """Une action de remédiation concrète."""

    title: str
    description: str
    command: str = ""  # Commande exacte à exécuter
    command_type: ActionType = ActionType.POWERSHELL
    priority: Priority = Priority.SHORT_TERM
    category: str = ""  # kerberoasting, delegation...
    reversible: bool = True  # Peut être annulée ?
    requires_reboot: bool = False
    rollback_command: str = ""
    reference: str = ""  # URL documentation


@dataclass
class RemediationPlan:
    """Plan de remédiation complet."""

    actions: list[RemediationAction] = field(default_factory=list)
    estimated_effort: str = ""  # "2h", "3 days"...
    risk_after_remediation: str = ""  # "LOW", "MEDIUM"...

    @property
    def immediate_actions(self) -> list[RemediationAction]:
        return [a for a in self.actions if a.priority == Priority.IMMEDIATE]

    @property
    def short_term_actions(self) -> list[RemediationAction]:
        return [a for a in self.actions if a.priority == Priority.SHORT_TERM]

    def summary(self) -> str:
        lines = [
            "=== Remediation Plan ===",
            f"Total actions: {len(self.actions)}",
            f"  Immediate (<24h): {len(self.immediate_actions)}",
            f"  Short-term (<1w): {len(self.short_term_actions)}",
            f"Estimated effort: {self.estimated_effort}",
            f"Risk after: {self.risk_after_remediation}",
            "",
        ]
        for action in self.actions:
            marker = {
                Priority.IMMEDIATE: "🔴",
                Priority.SHORT_TERM: "🟠",
                Priority.MEDIUM_TERM: "🟡",
                Priority.LONG_TERM: "🟢",
            }.get(action.priority, "❓")
            lines.append(f"{marker} [{action.priority.upper()}] {action.title}")
            if action.command:
                lines.append(f"   > {action.command}")
        return "\n".join(lines)


class RemediationAdvisor:
    """Conseiller en remédiation — génère des actions concrètes.

    Usage:
        advisor = RemediationAdvisor()
        plan = advisor.build_remediation_plan(
            vuln_report, rule_analysis, attack_paths
        )
    """

    def __init__(self, ai_engine=None) -> None:
        self.ai = ai_engine
        self._actions: list[RemediationAction] = []

    def build_remediation_plan(
        self,
        vuln_report=None,
        rule_analysis=None,
        attack_paths=None,
        domain_map=None,
    ) -> RemediationPlan:
        """Construit un plan de remédiation complet.

        Args:
            vuln_report: ScanReport vulnérabilités AD
            rule_analysis: RuleAnalysisReport firewall
            attack_paths: AttackPathAnalysis
            domain_map: DomainMap AD

        Returns:
            RemediationPlan avec actions ordonnées

        """
        self._actions = []

        # ── Actions depuis vuln_report ─────────────────────────
        if vuln_report:
            for finding in vuln_report.findings:
                if finding.category == "kerberoasting":
                    self._add_kerberoasting_remediation(finding)
                elif finding.category == "asrep_roasting":
                    self._add_asrep_remediation(finding)
                elif finding.category == "delegation":
                    self._add_delegation_remediation(finding)
                elif finding.category == "privileged_accounts":
                    self._add_privileged_remediation(finding)

        # ── Actions depuis rule_analysis ──────────────────────
        if rule_analysis:
            for finding in rule_analysis.findings:
                if finding.type == "any_any_rule":
                    self._add_any_any_remediation(finding)
                elif finding.type == "high_risk_port":
                    self._add_port_remediation(finding)

        # ── Trier par priorité ────────────────────────────────
        priority_order = {
            Priority.IMMEDIATE: 0,
            Priority.SHORT_TERM: 1,
            Priority.MEDIUM_TERM: 2,
            Priority.LONG_TERM: 3,
        }
        self._actions.sort(key=lambda a: priority_order.get(a.priority, 99))

        # Estimer l'effort
        total_minutes = len(self._actions) * 30
        if total_minutes < 120:
            effort = f"{total_minutes} minutes"
        elif total_minutes < 480:
            effort = f"{total_minutes // 60} hours"
        else:
            effort = f"{total_minutes // 480} days"

        return RemediationPlan(
            actions=self._actions,
            estimated_effort=effort,
            risk_after_remediation="MEDIUM",
        )

    # ── Générateurs d'actions ─────────────────────────────────

    def _add_kerberoasting_remediation(self, finding) -> None:
        """Remédiation Kerberoasting."""
        for account in finding.affected_assets[:5]:
            # Option 1: Supprimer les SPNs
            self._actions.append(
                RemediationAction(
                    title=f"Remove SPNs from {account}",
                    description=(
                        f"Remove all servicePrincipalNames from {account} to prevent Kerberoasting."
                    ),
                    command=(f"Set-ADUser -Identity '{account}' -ServicePrincipalNames @{{}}"),
                    command_type=ActionType.POWERSHELL,
                    priority=Priority.IMMEDIATE,
                    category="kerberoasting",
                    rollback_command=(
                        "# Restauration manuelle nécessaire — noter les SPNs avant suppression"
                    ),
                    reference="https://attack.mitre.org/techniques/T1558/003/",
                ),
            )

            # Option 2: Mot de passe renforcé
            self._actions.append(
                RemediationAction(
                    title=f"Rotate password for {account} (30+ chars)",
                    description=(
                        f"Set a strong password (30+ characters) for {account} "
                        f"to make Kerberoasting infeasible."
                    ),
                    command=(
                        f"$pw = Read-Host -AsSecureString; "
                        f"Set-ADAccountPassword -Identity '{account}' "
                        f"-NewPassword $pw -Reset"
                    ),
                    command_type=ActionType.POWERSHELL,
                    priority=Priority.SHORT_TERM,
                    category="kerberoasting",
                    reference="https://attack.mitre.org/mitigations/M1027/",
                ),
            )

    def _add_asrep_remediation(self, finding) -> None:
        """Remédiation AS-REP Roasting."""
        for account in finding.affected_assets[:5]:
            self._actions.append(
                RemediationAction(
                    title=f"Enable Kerberos preauthentication for {account}",
                    description=(
                        f"Disable 'Do not require Kerberos preauthentication' for {account}."
                    ),
                    command=(
                        f"Set-ADAccountControl -Identity '{account}' -DoesNotRequirePreAuth $false"
                    ),
                    command_type=ActionType.POWERSHELL,
                    priority=Priority.IMMEDIATE,
                    category="asrep_roasting",
                    rollback_command=(
                        f"Set-ADAccountControl -Identity '{account}' -DoesNotRequirePreAuth $true"
                    ),
                    reference="https://attack.mitre.org/techniques/T1558/004/",
                ),
            )

    def _add_delegation_remediation(self, finding) -> None:
        """Remédiation délégation non contrainte."""
        for host in finding.affected_assets[:5]:
            self._actions.append(
                RemediationAction(
                    title=f"Disable unconstrained delegation on {host}",
                    description=(
                        f"Remove TRUSTED_FOR_DELEGATION flag from {host}. "
                        f"Replace with constrained delegation if needed."
                    ),
                    command=(f"Set-ADComputer -Identity '{host}' -TrustedForDelegation $false"),
                    command_type=ActionType.POWERSHELL,
                    priority=Priority.SHORT_TERM,
                    category="delegation",
                    requires_reboot=True,
                    reference="https://attack.mitre.org/techniques/T1558/001/",
                ),
            )

    def _add_privileged_remediation(self, finding) -> None:
        """Remédiation comptes privilégiés."""
        self._actions.append(
            RemediationAction(
                title="Review and reduce privileged accounts",
                description=(
                    "Conduct an audit of all accounts with adminCount=1 "
                    "and reduce to the minimum necessary for operations."
                ),
                command=(
                    "Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount | "
                    "Export-Csv -Path 'admin_audit.csv'"
                ),
                command_type=ActionType.POWERSHELL,
                priority=Priority.MEDIUM_TERM,
                category="privileged_accounts",
                reference="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
            ),
        )

    def _add_any_any_remediation(self, finding) -> None:
        """Remédiation règles Any/Any firewall."""
        rule_name = finding.rule_names[0] if finding.rule_names else "unknown"
        self._actions.append(
            RemediationAction(
                title=f"Restrict firewall rule: {rule_name}",
                description=(
                    "Replace Any/Any source/destination with specific addresses and services."
                ),
                command=(
                    "# Via FortiGate CLI:\n"
                    "config firewall policy\n"
                    "  edit <rule_id>\n"
                    '    set srcaddr "specific-address"\n'
                    '    set dstaddr "specific-destination"\n'
                    '    set service "specific-service"\n'
                    "  next\n"
                    "end"
                ),
                command_type=ActionType.CLI,
                priority=Priority.SHORT_TERM,
                category="firewall",
                reference=f"Review rule: {rule_name}",
            ),
        )

    def _add_port_remediation(self, finding) -> None:
        """Remédiation ports à risque exposés."""
        self._actions.append(
            RemediationAction(
                title="Restrict high-risk port exposure",
                description=(
                    "Restrict source IPs for rules exposing RDP, SSH, and database ports."
                ),
                command=(
                    "Audit all firewall rules allowing ports 22, 3389, 1433, "
                    "3306, 5432. Add source IP restrictions."
                ),
                command_type=ActionType.MANUAL,
                priority=Priority.IMMEDIATE,
                category="firewall",
                reference="https://www.cisecurity.org/controls",
            ),
        )
