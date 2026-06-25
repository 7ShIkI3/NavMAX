"""
Tests pour CVSS Scorer et SARIF Exporter.
"""

import json

import pytest

from navmax.reporting.cvss_scorer import (
    CVSSScorer,
    CVSSScore,
    get_mitre_techniques,
    get_mitre_url,
)
from navmax.reporting.sarif_exporter import (
    SARIFExporter,
    SARIFResult,
    SARIF_VERSION,
)


# ── CVSS Scorer ─────────────────────────────────────────────────


class TestCVSSScore:
    """Tests dataclass CVSSScore."""

    def test_creation(self):
        score = CVSSScore(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            severity="Critical",
        )
        assert score.base_score == 9.8
        assert score.severity == "Critical"

    def test_badge_color_critical(self):
        score = CVSSScore("", 9.8, "Critical")
        assert score.badge_color == "#dc3545"

    def test_badge_color_high(self):
        score = CVSSScore("", 8.0, "High")
        assert score.badge_color == "#fd7e14"

    def test_badge_color_medium(self):
        score = CVSSScore("", 5.0, "Medium")
        assert score.badge_color == "#ffc107"

    def test_badge_color_low(self):
        score = CVSSScore("", 2.0, "Low")
        assert score.badge_color == "#6c757d"


class TestCVSSScorer:
    """Tests du calculateur CVSS."""

    def test_init(self):
        scorer = CVSSScorer()
        assert scorer is not None

    def test_calculate_fallback(self):
        """Le calcul en mode fallback (cvss lib absente)."""
        scorer = CVSSScorer()
        score = scorer.calculate(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        assert isinstance(score, CVSSScore)
        assert score.base_score > 7.0
        assert "AV:N" in score.vector_string

    def test_calculate_low_impact(self):
        scorer = CVSSScorer()
        score = scorer.calculate(av="N", ac="H", pr="H", ui="R", s="U", c="N", i="N", a="N")
        assert score.base_score < 3.0
        assert score.severity in ("None", "Low")

    def test_auto_score_critical(self):
        scorer = CVSSScorer()
        score = scorer.auto_score(severity="critical")
        assert score.base_score >= 9.0
        assert score.severity == "Critical"

    def test_auto_score_high(self):
        scorer = CVSSScorer()
        score = scorer.auto_score(severity="high")
        assert score.base_score >= 7.0

    def test_auto_score_medium(self):
        scorer = CVSSScorer()
        score = scorer.auto_score(severity="medium")
        assert 4.0 <= score.base_score < 7.0

    def test_auto_score_low(self):
        scorer = CVSSScorer()
        score = scorer.auto_score(severity="low")
        assert score.base_score < 4.0

    def test_auto_score_info(self):
        scorer = CVSSScorer()
        score = scorer.auto_score(severity="info")
        assert score.base_score == 0.0

    def test_auto_score_unknown(self):
        scorer = CVSSScorer()
        score = scorer.auto_score(severity="unknown_xyz")
        assert score.severity == "Medium"  # Fallback

    def test_severity_from_score(self):
        assert CVSSScorer._severity_from_score(9.8) == "Critical"
        assert CVSSScorer._severity_from_score(8.0) == "High"
        assert CVSSScorer._severity_from_score(5.0) == "Medium"
        assert CVSSScorer._severity_from_score(2.0) == "Low"
        assert CVSSScorer._severity_from_score(0.0) == "None"

    def test_heuristic_score(self):
        score = CVSSScorer._heuristic_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score > 5.0  # Beaucoup de H


# ── MITRE ATT&CK ────────────────────────────────────────────────


class TestMITRE:
    """Tests mapping MITRE ATT&CK."""

    def test_get_mitre_log4shell(self):
        techniques = get_mitre_techniques(["CVE-2021-44228"])
        assert "T1190" in techniques
        assert "T1059" in techniques

    def test_get_mitre_eternalblue(self):
        techniques = get_mitre_techniques(["CVE-2017-0144"])
        assert "T1210" in techniques

    def test_get_mitre_unknown(self):
        techniques = get_mitre_techniques(["CVE-9999-99999"])
        assert techniques == []

    def test_get_mitre_multiple(self):
        techniques = get_mitre_techniques(["CVE-2021-44228", "CVE-2017-0144"])
        assert len(techniques) >= 3
        assert "T1190" in techniques
        assert "T1210" in techniques

    def test_get_mitre_url(self):
        url = get_mitre_url("T1190")
        assert "attack.mitre.org" in url
        assert "T1190" in url


# ── SARIF ────────────────────────────────────────────────────────


class TestSARIFResult:
    """Tests dataclass SARIFResult."""

    def test_defaults(self):
        result = SARIFResult(
            rule_id="CVE-2021-44228",
            level="error",
            message="Log4Shell détecté",
            locations=[],
        )
        assert result.rule_id == "CVE-2021-44228"
        assert result.level == "error"
        assert result.cve_ids == []


class TestSARIFExporter:
    """Tests export SARIF."""

    def test_init(self):
        exporter = SARIFExporter()
        assert exporter.tool_name == "NavMAX"

    def test_export_empty(self):
        exporter = SARIFExporter()
        doc = exporter.export([])
        assert doc["version"] == SARIF_VERSION
        assert doc["$schema"] is not None
        assert len(doc["runs"]) == 1
        assert len(doc["runs"][0]["results"]) == 0

    def test_export_single_finding(self):
        exporter = SARIFExporter()
        findings = [{
            "cve_id": "CVE-2021-44228",
            "title": "Log4Shell RCE",
            "severity": "critical",
            "host": "app.example.com",
            "description": "Log4j RCE via JNDI injection",
        }]
        doc = exporter.export(findings)
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CVE-2021-44228"
        assert results[0]["level"] == "error"

    def test_export_multiple_severities(self):
        exporter = SARIFExporter()
        findings = [
            {"cve_id": "CRIT-001", "title": "Crit", "severity": "critical", "host": "x"},
            {"cve_id": "HIGH-001", "title": "High", "severity": "high", "host": "x"},
            {"cve_id": "MED-001", "title": "Med", "severity": "medium", "host": "x"},
            {"cve_id": "LOW-001", "title": "Low", "severity": "low", "host": "x"},
            {"cve_id": "INFO-001", "title": "Info", "severity": "info", "host": "x"},
        ]
        doc = exporter.export(findings)
        levels = [r["level"] for r in doc["runs"][0]["results"]]
        assert "error" in levels
        assert "warning" in levels
        assert "note" in levels

    def test_export_with_scan_info(self):
        exporter = SARIFExporter()
        findings = [{"cve_id": "CVE-2021-44228", "title": "Log4j", "severity": "critical", "host": "app.example.com"}]
        scan_info = {"target": "app.example.com", "duration_s": 45.2}
        doc = exporter.export(findings, scan_info)
        assert doc["runs"][0]["originalUriBaseIds"]["TARGET"]["uri"] == "app.example.com"

    def test_export_json_string(self):
        exporter = SARIFExporter()
        findings = [{"cve_id": "CVE-2021-44228", "title": "Log4j", "severity": "critical", "host": "x"}]
        json_str = exporter.export_json(findings)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["version"] == SARIF_VERSION

    def test_rules_deduplication(self):
        exporter = SARIFExporter()
        findings = [
            {"cve_id": "CVE-2021-44228", "title": "Log4j", "severity": "critical", "host": "a"},
            {"cve_id": "CVE-2021-44228", "title": "Log4j", "severity": "critical", "host": "b"},
        ]
        doc = exporter.export(findings)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        # Dédupliqué → 1 règle pour le même CVE
        assert len(rules) == 1

    def test_severity_to_sarif_level(self):
        assert SARIFExporter._severity_to_sarif_level("critical") == "error"
        assert SARIFExporter._severity_to_sarif_level("high") == "error"
        assert SARIFExporter._severity_to_sarif_level("medium") == "warning"
        assert SARIFExporter._severity_to_sarif_level("low") == "note"
        assert SARIFExporter._severity_to_sarif_level("info") == "none"
