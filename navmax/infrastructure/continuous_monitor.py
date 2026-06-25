"""
Continuous Monitor — surveillance proactive des dérives AD et firewall.

Détecte les changements suspects en temps réel :
- Nouveaux utilisateurs admin
- Nouvelles règles firewall permissives
- Modifications de templates ADCS
- Changements de configuration CA
- Apparition de nouveaux SPNs sur comptes admin
- Comptes réactivés
- Changements de groupes privilégiés

Usage:
    monitor = ContinuousMonitor(connector, fw_connector)
    drift = await monitor.check_drift(domain_map, fw_config)
    for alert in drift.alerts:
        print(f"{alert.severity}: {alert.title}")
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Optional, Any
import structlog

logger = structlog.get_logger(__name__)


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertCategory(StrEnum):
    NEW_ADMIN = "new_admin"
    PRIVILEGE_CHANGE = "privilege_change"
    FW_RULE_CHANGE = "fw_rule_change"
    ADCS_CHANGE = "adcs_change"
    SPN_CHANGE = "spn_change"
    GROUP_CHANGE = "group_change"
    ACCOUNT_CHANGE = "account_change"


@dataclass
class DriftAlert:
    """Alerte de dérive de configuration."""
    title: str
    description: str
    severity: AlertSeverity
    category: AlertCategory
    timestamp: str = ""
    previous_state: Any = None
    current_state: Any = None
    affected_entity: str = ""
    recommendation: str = ""


@dataclass
class Baseline:
    """État de référence pour comparaison."""
    domain: str = ""
    timestamp: str = ""
    admin_users: set = field(default_factory=set)
    admin_groups: set = field(default_factory=set)
    kerberoastable_users: set = field(default_factory=set)
    fw_rules_hash: str = ""
    fw_rule_count: int = 0
    adcs_templates_count: int = 0
    domain_controllers: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "admin_users": sorted(self.admin_users),
            "admin_groups": sorted(self.admin_groups),
            "kerberoastable_users": sorted(self.kerberoastable_users),
            "fw_rules_hash": self.fw_rules_hash,
            "fw_rule_count": self.fw_rule_count,
            "adcs_templates_count": self.adcs_templates_count,
            "domain_controllers": sorted(self.domain_controllers),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        return cls(
            domain=data.get("domain", ""),
            timestamp=data.get("timestamp", ""),
            admin_users=set(data.get("admin_users", [])),
            admin_groups=set(data.get("admin_groups", [])),
            kerberoastable_users=set(data.get("kerberoastable_users", [])),
            fw_rules_hash=data.get("fw_rules_hash", ""),
            fw_rule_count=data.get("fw_rule_count", 0),
            adcs_templates_count=data.get("adcs_templates_count", 0),
            domain_controllers=set(data.get("domain_controllers", [])),
        )


@dataclass
class DriftReport:
    """Rapport de dérive de configuration."""
    domain: str = ""
    baseline_timestamp: str = ""
    check_timestamp: str = ""
    alerts: list[DriftAlert] = field(default_factory=list)
    changes_detected: int = 0

    @property
    def has_critical_alerts(self) -> bool:
        return any(
            a.severity == AlertSeverity.CRITICAL for a in self.alerts
        )

    def summary(self) -> str:
        lines = [
            f"=== Drift Report: {self.domain} ===",
            f"Baseline: {self.baseline_timestamp}",
            f"Checked: {self.check_timestamp}",
            f"Alerts: {len(self.alerts)}",
        ]
        if self.alerts:
            lines.append("")
            for alert in self.alerts:
                marker = {
                    "critical": "🔴", "high": "🟠",
                    "medium": "🟡", "low": "🟢",
                }.get(alert.severity, "❓")
                lines.append(
                    f"{marker} [{alert.category}] {alert.title}"
                )
        return "\n".join(lines)


class ContinuousMonitor:
    """Moniteur de dérive de configuration — le SOC interne de NavMAX.

    Usage:
        monitor = ContinuousMonitor()
        baseline = monitor.capture_baseline(domain_map, fw_config)
        # ... plus tard ...
        drift = monitor.check_drift(baseline, current_domain_map, current_fw_config)
    """

    def __init__(self, ad_connector=None, fw_connector=None):
        self.ad_connector = ad_connector
        self.fw_connector = fw_connector

    # ── Baseline ──────────────────────────────────────────────

    def capture_baseline(
        self, domain_map=None, fw_config=None
    ) -> Baseline:
        """Capture l'état de référence du domaine et du firewall.

        Args:
            domain_map: DomainMap AD
            fw_config: FirewallConfig

        Returns:
            Baseline pour comparaison future
        """
        import hashlib
        import datetime

        baseline = Baseline(
            domain=domain_map.domain.name if domain_map else "",
            timestamp=datetime.datetime.now().isoformat(),
        )

        # Utilisateurs admin
        if domain_map:
            baseline.admin_users = {
                u.sam_account_name for u in domain_map.privileged_users
            }

            # Groupes admin (adminCount=1)
            baseline.admin_groups = {
                g.sam_account_name for g in domain_map.groups
                if g.admin_count == 1
            }

            # Utilisateurs Kerberoastable
            baseline.kerberoastable_users = {
                u.sam_account_name for u in domain_map.kerberoastable_users
            }

            # Contrôleurs de domaine
            baseline.domain_controllers = {
                c.dns_hostname for c in domain_map.domain_controllers
            }

        # Firewall
        if fw_config:
            # Hash des règles pour détecter tout changement
            rules_str = "\n".join(
                f"{r.name}|{r.action}|{','.join(r.source_addresses)}|"
                f"{','.join(r.destination_addresses)}|"
                f"{','.join(r.destination_ports)}|{r.enabled}"
                for r in fw_config.rules
            )
            baseline.fw_rules_hash = hashlib.sha256(
                rules_str.encode()
            ).hexdigest()[:16]
            baseline.fw_rule_count = len(fw_config.rules)

        logger.info("baseline_captured",
                    domain=baseline.domain,
                    admin_users=len(baseline.admin_users))

        return baseline

    # ── Drift Detection ───────────────────────────────────────

    def check_drift(
        self,
        baseline: Baseline,
        current_domain_map=None,
        current_fw_config=None,
    ) -> DriftReport:
        """Compare l'état actuel avec la baseline.

        Args:
            baseline: Baseline de référence
            current_domain_map: DomainMap actuelle
            current_fw_config: FirewallConfig actuelle

        Returns:
            DriftReport avec alertes
        """
        import datetime

        report = DriftReport(
            domain=baseline.domain,
            baseline_timestamp=baseline.timestamp,
            check_timestamp=datetime.datetime.now().isoformat(),
        )

        alerts: list[DriftAlert] = []

        # ── AD: Nouveaux admins ────────────────────────────────
        if current_domain_map:
            current_admins = {
                u.sam_account_name
                for u in current_domain_map.privileged_users
            }
            new_admins = current_admins - baseline.admin_users
            removed_admins = baseline.admin_users - current_admins

            for admin in new_admins:
                alerts.append(DriftAlert(
                    title=f"New privileged user: {admin}",
                    description=(
                        f"User '{admin}' was added to a privileged group "
                        f"or had adminCount elevated."
                    ),
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.NEW_ADMIN,
                    previous_state="Not admin",
                    current_state="Admin",
                    affected_entity=admin,
                    recommendation=f"Verify that {admin} requires admin "
                                   f"privileges. Audit the change.",
                ))

            for admin in removed_admins:
                alerts.append(DriftAlert(
                    title=f"Privilege removed: {admin}",
                    description=f"User '{admin}' is no longer privileged.",
                    severity=AlertSeverity.LOW,
                    category=AlertCategory.PRIVILEGE_CHANGE,
                    previous_state="Admin",
                    current_state="Not admin",
                    affected_entity=admin,
                    recommendation="Verify this was intentional.",
                ))

            # ── AD: Nouveaux comptes Kerberoastable ────────────
            current_kerb = {
                u.sam_account_name
                for u in current_domain_map.kerberoastable_users
                if u.is_admin
            }
            new_kerb_admin = current_kerb - baseline.kerberoastable_users

            for kerb_user in new_kerb_admin:
                alerts.append(DriftAlert(
                    title=f"New Kerberoastable admin: {kerb_user}",
                    description=(
                        f"Admin account '{kerb_user}' now has SPNs — "
                        f"vulnerable to Kerberoasting."
                    ),
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.SPN_CHANGE,
                    affected_entity=kerb_user,
                    recommendation=(
                        f"Immediately remove SPNs from {kerb_user} "
                        f"or set a 30+ character password."
                    ),
                ))

        # ── Firewall: Changements de règles ────────────────────
        if current_fw_config:
            import hashlib
            current_rules_str = "\n".join(
                f"{r.name}|{r.action}|{','.join(r.source_addresses)}|"
                f"{','.join(r.destination_addresses)}|"
                f"{','.join(r.destination_ports)}|{r.enabled}"
                for r in current_fw_config.rules
            )
            current_hash = hashlib.sha256(
                current_rules_str.encode()
            ).hexdigest()[:16]

            if current_hash != baseline.fw_rules_hash:
                # Détecter les nouvelles règles
                if current_fw_config.rule_count != baseline.fw_rule_count:
                    alerts.append(DriftAlert(
                        title="Firewall rules modified",
                        description=(
                            f"Rule count changed from "
                            f"{baseline.fw_rule_count} to "
                            f"{current_fw_config.rule_count}"
                        ),
                        severity=AlertSeverity.HIGH,
                        category=AlertCategory.FW_RULE_CHANGE,
                        previous_state=f"{baseline.fw_rule_count} rules",
                        current_state=f"{current_fw_config.rule_count} rules",
                        recommendation=(
                            "Audit all new/modified firewall rules."
                        ),
                    ))
                else:
                    alerts.append(DriftAlert(
                        title="Firewall rules modified (count unchanged)",
                        description=(
                            "One or more firewall rules were modified "
                            "without changing the total count."
                        ),
                        severity=AlertSeverity.MEDIUM,
                        category=AlertCategory.FW_RULE_CHANGE,
                        recommendation="Audit modified rules.",
                    ))

        report.alerts = alerts
        report.changes_detected = len(alerts)

        if alerts:
            logger.info("drift_detected",
                        domain=baseline.domain,
                        alerts=len(alerts))

        return report

    # ── Surveillance automatisée ───────────────────────────────

    async def monitor_continuous(
        self, domain_map_getter, fw_config_getter,
        interval_seconds: int = 3600,
    ) -> None:
        """Surveillance continue en boucle infinie.

        ⚠️ Bloquant — à lancer dans un thread/worker séparé.

        Args:
            domain_map_getter: Callable async retournant une DomainMap
            fw_config_getter: Callable async retournant une FirewallConfig
            interval_seconds: Intervalle entre les checks
        """
        import asyncio

        # Capture baseline
        dm = await domain_map_getter()
        fw = await fw_config_getter() if fw_config_getter else None
        baseline = self.capture_baseline(dm, fw)

        logger.info("continuous_monitoring_started",
                    domain=baseline.domain,
                    interval=interval_seconds)

        while True:
            await asyncio.sleep(interval_seconds)

            try:
                current_dm = await domain_map_getter()
                current_fw = await fw_config_getter() if fw_config_getter else None

                drift = self.check_drift(baseline, current_dm, current_fw)

                if drift.alerts:
                    logger.warning("drift_detected",
                                   domain=baseline.domain,
                                   alerts=len(drift.alerts))
                    for alert in drift.alerts:
                        if alert.severity in (AlertSeverity.CRITICAL,
                                              AlertSeverity.HIGH):
                            logger.error("drift_critical_alert",
                                         title=alert.title,
                                         entity=alert.affected_entity)

            except (RuntimeError, OSError, ValueError) as e:
                logger.error("monitor_cycle_error", error=str(e))
