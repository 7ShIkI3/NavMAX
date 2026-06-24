"""
Tests for BloodHound export + Infrastructure modules.
"""

import pytest
import json
import tempfile
import os


# ═══════════════════════════════════════════════════════════════
# BloodHound Export
# ═══════════════════════════════════════════════════════════════

class TestBloodHoundExport:
    def _get_graph(self):
        from navmax.ad.trust_graph import ADTrustGraph
        from tests.test_ad import TestDomainMap
        dm = TestDomainMap()._build_domain_map()
        graph = ADTrustGraph()
        graph.build(dm)
        return graph

    def test_export_has_correct_structure(self):
        from navmax.ad.bloodhound_export import BloodHoundExporter
        exporter = BloodHoundExporter()
        graph = self._get_graph()
        data = exporter.export(graph)

        assert "data" in data
        assert "meta" in data
        assert len(data["data"]) == 1
        assert "Nodes" in data["data"][0]
        assert "Edges" in data["data"][0]

    def test_export_nodes_have_labels(self):
        from navmax.ad.bloodhound_export import BloodHoundExporter
        exporter = BloodHoundExporter()
        graph = self._get_graph()
        data = exporter.export(graph)

        nodes = data["data"][0]["Nodes"]
        labels = {n["Label"] for n in nodes.values()}
        assert "User" in labels or "Group" in labels

    def test_export_edges_have_kind(self):
        from navmax.ad.bloodhound_export import BloodHoundExporter
        exporter = BloodHoundExporter()
        graph = self._get_graph()
        data = exporter.export(graph)

        edges = data["data"][0]["Edges"]
        assert len(edges) > 0
        for edge in edges:
            assert "Kind" in edge
            assert isinstance(edge["Kind"], int)

    def test_save_to_file(self):
        from navmax.ad.bloodhound_export import BloodHoundExporter
        exporter = BloodHoundExporter()
        graph = self._get_graph()

        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write("{}")
            tmp_path = f.name

        try:
            data = exporter.export(graph)
            result = exporter.save(data, tmp_path)
            assert result.file_size_bytes > 0
            assert result.node_count > 0
        finally:
            os.unlink(tmp_path)

    def test_export_and_save(self):
        from navmax.ad.bloodhound_export import BloodHoundExporter
        exporter = BloodHoundExporter()
        graph = self._get_graph()

        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False
        ) as f:
            tmp_path = f.name

        try:
            result = exporter.export_and_save(graph, tmp_path)
            assert result.node_count > 0
            assert result.edge_count > 0
            # Vérifier que le fichier est du JSON valide
            with open(tmp_path) as f:
                json.load(f)
        finally:
            os.unlink(tmp_path)

    def test_empty_graph_export(self):
        from navmax.ad.bloodhound_export import BloodHoundExporter
        from navmax.ad.trust_graph import ADTrustGraph
        exporter = BloodHoundExporter()
        empty_graph = ADTrustGraph()
        data = exporter.export(empty_graph)
        assert data["meta"]["counts"]["nodes"] == 0


# ═══════════════════════════════════════════════════════════════
# Infrastructure: Impact Reporter
# ═══════════════════════════════════════════════════════════════

class TestImpactReporter:
    def _get_domain_map(self):
        from tests.test_ad import TestDomainMap
        return TestDomainMap()._build_domain_map()

    @pytest.mark.asyncio
    async def test_generate_report(self):
        from navmax.infrastructure.impact_reporter import ImpactReporter
        dm = self._get_domain_map()
        reporter = ImpactReporter()
        report = await reporter.generate(domain_map=dm)
        assert report.overall_risk in ("critical", "high", "medium", "low")
        assert len(report.executive_summary) > 0
        assert len(report.recommendations) > 0

    @pytest.mark.asyncio
    async def test_report_string_representation(self):
        from navmax.infrastructure.impact_reporter import ImpactReporter
        dm = self._get_domain_map()
        reporter = ImpactReporter()
        report = await reporter.generate(domain_map=dm)
        report_str = str(report)
        assert "EXECUTIVE SUMMARY" in report_str
        assert "RECOMMENDATIONS" in report_str or "BUSINESS IMPACTS" in report_str

    def test_business_impact_dataclass(self):
        from navmax.infrastructure.impact_reporter import (
            BusinessImpact, ImpactLevel,
        )
        impact = BusinessImpact(
            title="Test",
            description="Test impact",
            level=ImpactLevel.CRITICAL,
            affected_assets=["asset1"],
            financial_risk="~500k€",
            remediation_priority=1,
        )
        assert impact.level == "critical"
        assert impact.remediation_priority == 1


# ═══════════════════════════════════════════════════════════════
# Infrastructure: Remediation Advisor
# ═══════════════════════════════════════════════════════════════

class TestRemediationAdvisor:
    def test_empty_plan(self):
        from navmax.infrastructure.remediation_advisor import (
            RemediationAdvisor,
        )
        advisor = RemediationAdvisor()
        plan = advisor.build_remediation_plan()
        assert len(plan.actions) == 0

    @pytest.mark.asyncio
    async def test_plan_from_vuln_report(self):
        from navmax.infrastructure.remediation_advisor import RemediationAdvisor
        from navmax.ad.vuln_scanner import ADVulnScanner
        from tests.test_ad import TestDomainMap

        dm = TestDomainMap()._build_domain_map()
        scanner = ADVulnScanner()
        vuln_report = await scanner.scan_all(dm)

        advisor = RemediationAdvisor()
        plan = advisor.build_remediation_plan(vuln_report=vuln_report)

        # Doit avoir au moins des actions Kerberoasting
        assert len(plan.actions) >= 1
        # Vérifier qu'il y a des actions immédiates
        assert len(plan.immediate_actions) >= 1 or len(plan.short_term_actions) >= 1

    def test_plan_summary(self):
        from navmax.infrastructure.remediation_advisor import (
            RemediationAdvisor, RemediationAction, Priority, ActionType,
        )
        advisor = RemediationAdvisor()
        # Hack direct pour tester le summary sans rebuild
        action = RemediationAction(
            title="Fix critical issue",
            description="desc",
            command="Fix-It",
            priority=Priority.IMMEDIATE,
            command_type=ActionType.POWERSHELL,
        )
        advisor._actions = [action]
        plan = advisor.build_remediation_plan()
        # build_remediation_plan vide _actions → on re-set
        advisor._actions = [action]
        # Utiliser directement la propriété summary après rebuild
        plan2 = RemediationAdvisor.__new__(RemediationAdvisor)
        plan2._actions = [action]
        # Utiliser la dataclass RemediationPlan directement
        from navmax.infrastructure.remediation_advisor import RemediationPlan
        plan3 = RemediationPlan(
            actions=[action],
            estimated_effort="30 minutes",
            risk_after_remediation="LOW",
        )
        summary = plan3.summary()
        assert "IMMEDIATE" in summary
        assert "Fix critical issue" in summary

    def test_action_dataclass(self):
        from navmax.infrastructure.remediation_advisor import (
            RemediationAction, ActionType, Priority,
        )
        action = RemediationAction(
            title="Test action",
            description="Test description",
            command="Get-Process",
            command_type=ActionType.POWERSHELL,
            priority=Priority.IMMEDIATE,
            category="kerberoasting",
            rollback_command="Undo-It",
        )
        assert action.priority == "immediate"
        assert action.command_type == "powershell"


# ═══════════════════════════════════════════════════════════════
# Infrastructure: Continuous Monitor
# ═══════════════════════════════════════════════════════════════

class TestContinuousMonitor:
    def _get_domain_map(self):
        from tests.test_ad import TestDomainMap
        return TestDomainMap()._build_domain_map()

    def test_capture_baseline(self):
        from navmax.infrastructure.continuous_monitor import ContinuousMonitor
        dm = self._get_domain_map()
        monitor = ContinuousMonitor()
        baseline = monitor.capture_baseline(domain_map=dm)

        assert baseline.domain == "corp.local"
        assert len(baseline.admin_users) >= 1  # Administrator
        assert len(baseline.kerberoastable_users) >= 1  # svc_web

    def test_baseline_serialization(self):
        from navmax.infrastructure.continuous_monitor import (
            ContinuousMonitor, Baseline,
        )
        dm = self._get_domain_map()
        monitor = ContinuousMonitor()
        baseline = monitor.capture_baseline(domain_map=dm)

        d = baseline.to_dict()
        restored = Baseline.from_dict(d)
        assert restored.domain == baseline.domain
        assert restored.admin_users == baseline.admin_users

    def test_check_drift_no_changes(self):
        from navmax.infrastructure.continuous_monitor import ContinuousMonitor
        dm = self._get_domain_map()
        monitor = ContinuousMonitor()
        baseline = monitor.capture_baseline(domain_map=dm)

        # Même DomainMap → pas de dérive
        drift = monitor.check_drift(baseline, current_domain_map=dm)
        assert len(drift.alerts) == 0
        assert drift.changes_detected == 0

    def test_drift_report_summary(self):
        from navmax.infrastructure.continuous_monitor import (
            ContinuousMonitor, DriftReport,
        )
        report = DriftReport(domain="test.local")
        summary = report.summary()
        assert "test.local" in summary

    def test_alert_dataclass(self):
        from navmax.infrastructure.continuous_monitor import (
            DriftAlert, AlertSeverity, AlertCategory,
        )
        alert = DriftAlert(
            title="New admin detected",
            description="A new admin was added",
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.NEW_ADMIN,
            affected_entity="new_admin",
            recommendation="Investigate immediately",
        )
        assert alert.severity == "critical"
        assert alert.category == "new_admin"

    def test_baseline_empty_domain(self):
        from navmax.infrastructure.continuous_monitor import ContinuousMonitor
        monitor = ContinuousMonitor()
        baseline = monitor.capture_baseline()
        assert baseline.domain == ""
        assert len(baseline.admin_users) == 0
