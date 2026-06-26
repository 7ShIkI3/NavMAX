"""Tests pour P6.2 (AIReportGenerator) et P6.3 (Integrations)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from navmax.integrations import (
    AlertData,
    IntegrationHub,
    MISPConnector,
    TheHiveConnector,
)
from navmax.reporting.generator import (
    AIReportGenerator,
    AuditReport,
    ReportFinding,
)

# ═══════════════════════════════════════════════════════════════
# AIReportGenerator
# ═══════════════════════════════════════════════════════════════


class TestAuditReport:
    def test_empty(self) -> None:
        r = AuditReport(title="Test")
        assert r.critical_count == 0
        assert r.high_count == 0

    def test_critical_count(self) -> None:
        r = AuditReport(
            title="Test",
            findings=[
                ReportFinding(title="C1", severity="CRITICAL"),
                ReportFinding(title="H1", severity="HIGH"),
                ReportFinding(title="C2", severity="CRITICAL"),
            ],
        )
        assert r.critical_count == 2
        assert r.high_count == 1


class TestAIReportGenerator:
    @pytest.fixture
    def ai_engine(self):
        from navmax.ai.providers.base import GenerateResult, ProviderType

        engine = AsyncMock()
        import json

        engine.generate = AsyncMock(
            return_value=GenerateResult(
                text=json.dumps(
                    {
                        "executive_summary": "Test summary",
                        "methodology": "Automated scan",
                        "findings": [
                            {
                                "title": "Open SSH",
                                "severity": "MEDIUM",
                                "description": "SSH port open",
                                "cve": None,
                                "affected": "10.0.0.1:22",
                                "evidence": "",
                                "remediation": "Restrict SSH access",
                            },
                        ],
                        "recommendations": [
                            {"priority": 1, "action": "Patch", "details": "Update SSH"},
                        ],
                    },
                ),
                model="mock",
                provider=ProviderType.OLLAMA,
                tokens_used=100,
                tokens_per_second=50.0,
                finish_reason="stop",
            ),
        )
        return engine

    @pytest.fixture
    def mission_result(self):
        from navmax.orchestrator.engine import MissionResult

        return MissionResult(
            objective="Audit network",
            target="10.0.0.0/24",
            phases_executed=2,
            phases_succeeded=2,
            results={"p1": {"services": [{"port": 22, "service": "ssh", "version": "8.9"}]}},
        )

    @pytest.mark.asyncio
    async def test_generate_basic(self, ai_engine, mission_result) -> None:
        gen = AIReportGenerator(ai_engine)
        report = await gen.generate(mission_result)
        assert report.title != ""
        assert "Audit" in report.title
        assert report.executive_summary == "Test summary"
        assert len(report.findings) == 1
        assert report.findings[0].severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_generate_no_findings(self, mission_result) -> None:
        """Sans findings, rapport simple sans appeler l'IA."""
        ai = AsyncMock()
        gen = AIReportGenerator(ai)
        mission_result.results = {}
        report = await gen.generate(mission_result)
        assert report.executive_summary != ""
        ai.generate.assert_not_called()

    @pytest.mark.asyncio
    async def test_to_markdown(self, ai_engine, mission_result) -> None:
        gen = AIReportGenerator(ai_engine)
        report = await gen.generate(mission_result)
        md = gen.to_markdown(report)
        assert "# " in md
        assert "Executive Summary" in md
        assert "Findings" in md
        assert "MEDIUM" in md

    @pytest.mark.asyncio
    async def test_to_html(self, ai_engine, mission_result) -> None:
        gen = AIReportGenerator(ai_engine)
        report = await gen.generate(mission_result)
        html = gen.to_html(report)
        assert "<!DOCTYPE html>" in html
        assert "<title>" in html
        assert "Executive Summary" in html


# ═══════════════════════════════════════════════════════════════
# Integrations
# ═══════════════════════════════════════════════════════════════


class TestAlertData:
    def test_defaults(self) -> None:
        alert = AlertData(title="Test", description="Desc")
        assert alert.severity == 2
        assert alert.source == "NavMAX"
        assert alert.tags == []
        assert alert.indicators == []

    def test_with_indicators(self) -> None:
        alert = AlertData(
            title="Redis unauth",
            description="Redis accessible without auth",
            severity=3,
            indicators=[{"type": "ip", "value": "10.0.0.1"}],
        )
        assert len(alert.indicators) == 1
        assert alert.severity == 3


class TestTheHiveConnector:
    def test_init(self) -> None:
        c = TheHiveConnector("https://hive.example.com", "key123")
        assert c.base_url == "https://hive.example.com"
        assert c.api_key == "key123"

    @pytest.mark.asyncio
    async def test_health_check_fails_gracefully(self) -> None:
        c = TheHiveConnector("https://invalid.local", "key")
        ok = await c.health_check()
        assert ok is False


class TestMISPConnector:
    def test_init(self) -> None:
        c = MISPConnector("https://misp.example.com", "key456")
        assert c.base_url == "https://misp.example.com"

    @pytest.mark.asyncio
    async def test_health_check_fails_gracefully(self) -> None:
        c = MISPConnector("https://invalid.local", "key")
        ok = await c.health_check()
        assert ok is False


class TestIntegrationHub:
    def test_add_connector(self) -> None:
        hub = IntegrationHub()
        hub.add_connector("hive", MagicMock())
        assert "hive" in hub.connectors

    def test_remove_connector(self) -> None:
        hub = IntegrationHub()
        hub.add_connector("test", MagicMock())
        hub.remove_connector("test")
        assert "test" not in hub.connectors

    def test_multiple_connectors(self) -> None:
        hub = IntegrationHub()
        hub.add_connector("a", MagicMock())
        hub.add_connector("b", MagicMock())
        assert len(hub.connectors) == 2

    @pytest.mark.asyncio
    async def test_send_alert(self) -> None:
        hub = IntegrationHub()
        mock = AsyncMock()
        mock.create_alert = AsyncMock(return_value="alert-123")
        hub.add_connector("hive", mock)

        alert = AlertData(title="Test", description="Test alert")
        results = await hub.send_alert(alert)
        assert results["hive"] == "alert-123"
        mock.create_alert.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_alert_handles_failure(self) -> None:
        """Les échecs de connector sont loggés sans crasher (refactoring: graceful degradation)."""
        hub = IntegrationHub()
        mock = AsyncMock()
        mock.create_alert = AsyncMock(side_effect=Exception("Connection refused"))
        hub.add_connector("hive", mock)

        alert = AlertData(title="Test", description="Test")
        # Le refactoring loggue l'erreur sans crasher
        results = await hub.send_alert(alert)
        assert "hive" in results
