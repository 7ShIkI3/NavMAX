"""
Tests pour le module Firewall.
"""

import pytest
from navmax.firewall.base import (
    FirewallConfig, FirewallRule, FirewallInterface, FirewallAddress,
    FirewallUser, CVECheck, FirewallVendor, RuleAction, RuleSeverity, Protocol,
)
from navmax.firewall.rule_analyzer import (
    RuleAnalyzer, RuleFinding, RuleAnalysisReport, FindingType,
)
from navmax.firewall.correlation import (
    ADCorrelator, CorrelationFinding, CorrelationReport, CorrelationSeverity,
)


# ═══════════════════════════════════════════════════════════════
# FirewallConfig
# ═══════════════════════════════════════════════════════════════

class TestFirewallConfig:
    def _build_config(self) -> FirewallConfig:
        return FirewallConfig(
            vendor=FirewallVendor.FORTINET,
            hostname="fw01.corp.local",
            model="FortiGate 100F",
            version="v7.2.8",
            rules=[
                FirewallRule(
                    id="1", name="Allow-All-Outbound",
                    action=RuleAction.ALLOW,
                    source_addresses=["all"],
                    destination_addresses=["all"],
                    destination_ports=["any"], enabled=True, position=0,
                ),
                FirewallRule(
                    id="2", name="Allow-RDP-to-DC",
                    action=RuleAction.ALLOW,
                    source_addresses=["any"],
                    destination_addresses=["dc01.corp.local"],
                    destination_ports=["3389"], enabled=True, position=1,
                ),
                FirewallRule(
                    id="3", name="Deny-All",
                    action=RuleAction.DENY,
                    source_addresses=["any"],
                    destination_addresses=["any"],
                    destination_ports=["any"], enabled=True, position=2,
                ),
            ],
            interfaces=[
                FirewallInterface(name="wan1", ip_address="203.0.113.1",
                                  zone="wan"),
                FirewallInterface(name="internal1", ip_address="10.0.0.1",
                                  zone="internal"),
            ],
            addresses=[
                FirewallAddress(name="dc01", value="10.0.0.10"),
                FirewallAddress(name="vpn-pool", value="10.0.100.0/24"),
            ],
            users=[
                FirewallUser(name="admin", profile="super_admin"),
            ],
        )

    def test_enabled_rules(self):
        config = self._build_config()
        assert len(config.enabled_rules) == 3

    def test_allow_rules(self):
        config = self._build_config()
        assert len(config.allow_rules) == 2

    def test_risky_rules(self):
        config = self._build_config()
        risky = config.risky_rules
        # Allow-All-Outbound: any src + any dst = risky
        # Allow-RDP-to-DC: exposes port 3389 = risky
        assert len(risky) >= 1

    def test_summary(self):
        config = self._build_config()
        summary = config.summary()
        assert "fw01.corp.local" in summary
        assert "FortiGate 100F" in summary

    def test_empty_config(self):
        config = FirewallConfig(vendor=FirewallVendor.GENERIC)
        assert len(config.rules) == 0
        assert config.summary()


# ═══════════════════════════════════════════════════════════════
# FortiGate CVE Check
# ═══════════════════════════════════════════════════════════════

class TestFortiGateCVE:
    @pytest.mark.asyncio
    async def test_cve_check_vulnerable(self):
        from navmax.firewall.fortigate import FortiGateConnector
        fgt = FortiGateConnector(host="10.0.0.1")
        # Version vulnérable à CVE-2022-40684 (7.2.0-7.2.1)
        checks = await fgt.check_cves("v7.2.0")
        assert len(checks) > 0
        has_cve_2022 = any(
            c.cve_id == "CVE-2022-40684" and c.vulnerable
            for c in checks
        )
        assert has_cve_2022

    @pytest.mark.asyncio
    async def test_cve_check_patched(self):
        from navmax.firewall.fortigate import FortiGateConnector
        fgt = FortiGateConnector(host="10.0.0.1")
        # Version patchée pour CVE-2022-40684 (7.2.8)
        checks = await fgt.check_cves("v7.2.8")
        has_cve_2022 = any(
            c.cve_id == "CVE-2022-40684" and c.vulnerable
            for c in checks
        )
        assert not has_cve_2022

    @pytest.mark.asyncio
    async def test_cve_check_unknown_version(self):
        from navmax.firewall.fortigate import FortiGateConnector
        fgt = FortiGateConnector(host="10.0.0.1")
        checks = await fgt.check_cves("")
        # Version inconnue → au moins une CVE marquée vulnérable
        assert any(c.vulnerable for c in checks)

    def test_version_comparison(self):
        from navmax.firewall.fortigate import FortiGateConnector
        fgt = FortiGateConnector(host="10.0.0.1")

        assert fgt._version_lt([7, 2, 0], [7, 2, 16]) is True
        assert fgt._version_lt([7, 2, 20], [7, 2, 16]) is False
        assert fgt._version_lte([7, 2, 16], [7, 2, 16]) is True
        assert fgt._version_gte([7, 2, 16], [7, 2, 0]) is True


# ═══════════════════════════════════════════════════════════════
# StormShield CVE Check
# ═══════════════════════════════════════════════════════════════

class TestStormShieldCVE:
    @pytest.mark.asyncio
    async def test_cve_check_vulnerable(self):
        from navmax.firewall.stormshield import StormShieldConnector
        sns = StormShieldConnector(host="10.0.0.1")
        checks = await sns.check_cves("4.3.8")
        has_cve = any(
            c.cve_id == "CVE-2024-29867" and c.vulnerable
            for c in checks
        )
        assert has_cve

    @pytest.mark.asyncio
    async def test_cve_check_patched(self):
        from navmax.firewall.stormshield import StormShieldConnector
        sns = StormShieldConnector(host="10.0.0.1")
        checks = await sns.check_cves("4.7.2")
        has_cve = any(
            c.cve_id == "CVE-2024-29867" and c.vulnerable
            for c in checks
        )
        assert not has_cve


# ═══════════════════════════════════════════════════════════════
# RuleAnalyzer
# ═══════════════════════════════════════════════════════════════

class TestRuleAnalyzer:
    def _build_config(self) -> FirewallConfig:
        return FirewallConfig(
            vendor=FirewallVendor.FORTINET,
            hostname="fw01",
            rules=[
                FirewallRule(id="1", name="Allow-DB",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["db-server"],
                             destination_ports=["3306"],
                             enabled=True, position=0),
                FirewallRule(id="2", name="Allow-All-Internal",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["any"],
                             destination_ports=["any"],
                             enabled=True, position=1),
                FirewallRule(id="3", name="Allow-RDP",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["any"],
                             destination_ports=["3389"],
                             enabled=True, position=2),
            ],
        )

    def test_any_any_detection(self):
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(self._build_config())
        any_any = [f for f in report.findings
                   if f.type == FindingType.ANY_ANY_RULE]
        assert len(any_any) >= 1

    def test_high_risk_port_detection(self):
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(self._build_config())
        high_risk = [f for f in report.findings
                     if f.type == FindingType.HIGH_RISK_PORT]
        # Port 3306 (MySQL) et 3389 (RDP) = 2 règles
        assert len(high_risk) >= 1

    def test_risk_score_computation(self):
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(self._build_config())
        assert 0 <= report.risk_score <= 100

    def test_summary_format(self):
        analyzer = RuleAnalyzer()
        report = analyzer.analyze(self._build_config())
        summary = report.summary()
        assert "fw01" in summary
        assert "Findings:" in summary

    def test_empty_config(self):
        analyzer = RuleAnalyzer()
        config = FirewallConfig(vendor=FirewallVendor.GENERIC)
        report = analyzer.analyze(config)
        assert len(report.findings) == 0


# ═══════════════════════════════════════════════════════════════
# ADCorrelator
# ═══════════════════════════════════════════════════════════════

class TestADCorrelator:
    def _build_domain_map(self):
        from navmax.ad.connector import (
            ADUser, ADGroup, ADComputer, ADDomain, ADTrust,
        )
        from navmax.ad.enumerator import DomainMap

        domain = ADDomain(name="corp.local", netbios_name="CORP")
        admin = ADUser(
            dn="CN=Admin,CN=Users,DC=corp,DC=local",
            sam_account_name="admin", admin_count=1,
            member_of=["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        )
        svc = ADUser(
            dn="CN=Svc,CN=Users,DC=corp,DC=local",
            sam_account_name="svc_web",
            service_principal_names=["HTTP/web.corp.local"],
        )
        user = ADUser(
            dn="CN=User,CN=Users,DC=corp,DC=local",
            sam_account_name="jdoe",
        )
        da = ADGroup(
            dn="CN=Domain Admins,CN=Users,DC=corp,DC=local",
            sam_account_name="Domain Admins",
            members=[admin.dn],
        )
        return DomainMap(
            domain=domain,
            users=[admin, svc, user],
            groups=[da],
            computers=[],
            ous=[], gpos=[], trusts=[],
            _users_by_dn={admin.dn: admin, svc.dn: svc, user.dn: user},
            _groups_by_dn={da.dn: da},
            _groups_by_sam={"Domain Admins": da},
        )

    def _build_fw_config(self) -> FirewallConfig:
        return FirewallConfig(
            vendor=FirewallVendor.FORTINET,
            hostname="fw01",
            rules=[
                FirewallRule(id="1", name="Allow-Any",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["any"],
                             destination_ports=["any"],
                             enabled=True),
                FirewallRule(id="2", name="Allow-DB",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["database-server"],
                             destination_ports=["3306"],
                             enabled=True),
                FirewallRule(id="3", name="Allow-RDP-DC",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["dc01"],
                             destination_ports=["3389"],
                             enabled=True),
                FirewallRule(id="4", name="Allow-VPN",
                             action=RuleAction.ALLOW,
                             source_addresses=["any"],
                             destination_addresses=["vpn-gateway"],
                             destination_ports=["443"],
                             enabled=True),
            ],
        )

    def test_correlation_finds_risks(self):
        correlator = ADCorrelator()
        dm = self._build_domain_map()
        fw = self._build_fw_config()
        report = correlator.correlate(dm, fw)
        assert len(report.findings) >= 1

    def test_correlation_report_summary(self):
        correlator = ADCorrelator()
        dm = self._build_domain_map()
        fw = self._build_fw_config()
        report = correlator.correlate(dm, fw)
        summary = report.summary()
        assert "corp.local" in summary
        assert "fw01" in summary

    def test_correlation_severity_present(self):
        correlator = ADCorrelator()
        dm = self._build_domain_map()
        fw = self._build_fw_config()
        report = correlator.correlate(dm, fw)
        for f in report.findings:
            assert f.severity in ("critical", "high", "medium", "low")

    def test_firewall_vendor_enum(self):
        assert FirewallVendor.FORTINET == "fortinet"
        assert FirewallVendor.STORMSHIELD == "stormshield"

    def test_rule_action_enum(self):
        assert RuleAction.ALLOW == "allow"
        assert RuleAction.DENY == "deny"

    def test_cve_check_dataclass(self):
        cve = CVECheck(
            cve_id="CVE-2024-0000",
            title="Test CVE",
            severity="critical",
            vulnerable=True,
            version_affected="< 7.0",
            current_version="6.9",
            cvss_score=9.8,
        )
        assert cve.vulnerable is True
        assert cve.cvss_score == 9.8

    def test_firewall_address_types(self):
        addr_ip = FirewallAddress(name="host1", value="10.0.0.1", type="ip")
        addr_subnet = FirewallAddress(name="net1", value="10.0.0.0/24", type="subnet")
        addr_fqdn = FirewallAddress(name="www", value="example.com", type="fqdn")
        assert addr_ip.type == "ip"
        assert addr_subnet.type == "subnet"
        assert addr_fqdn.type == "fqdn"
