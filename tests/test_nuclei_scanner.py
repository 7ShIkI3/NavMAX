"""Tests pour NucleiScanner — wrapper asynchrone autour du binaire nuclei."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navmax.scanner.nuclei_scanner import (
    NucleiFinding,
    NucleiNotFoundError,
    NucleiScanner,
    NucleiTimeoutError,
)

# ── Sample nuclei JSON lines ────────────────────────────────────

SIMPLE_FINDING_JSON = {
    "template-id": "tomcat-detect",
    "templateID": "tomcat-detect",
    "info": {
        "name": "Apache Tomcat Detection",
        "severity": "info",
        "description": "Apache Tomcat server was detected.",
    },
    "host": "https://10.0.0.1:8080",
    "matched-at": "https://10.0.0.1:8080/",
    "matcher-name": "tomcat-server-header",
    "extracted-results": ["Apache-Coyote/1.1"],
    "curl-command": "curl -k -X GET 'https://10.0.0.1:8080/'",
}

CVE_FINDING_JSON = {
    "template-id": "CVE-2023-22515",
    "templateID": "CVE-2023-22515",
    "info": {
        "name": "Confluence Data Center & Server - Privilege Escalation",
        "severity": "critical",
        "description": "Broken access control in Confluence Data Center/Server allowing privilege escalation.",
        "classification": {
            "cvss-score": 9.8,
            "cve-id": ["CVE-2023-22515"],
        },
        "reference": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
            "https://confluence.atlassian.com/",
        ],
    },
    "host": "https://10.0.0.1:8090",
    "matched-at": "https://10.0.0.1:8090/setup",
    "matcher-name": "confluence-setup-page",
    "extracted-results": [],
    "curl-command": "curl -k -X GET 'https://10.0.0.1:8090/setup'",
}

MEDIUM_FINDING_JSON = {
    "template-id": "ssl-weak-ciphers",
    "templateID": "ssl-weak-ciphers",
    "info": {
        "name": "SSL Weak Ciphers",
        "severity": "medium",
        "description": "The server supports weak SSL ciphers.",
        "classification": {
            "cvss-score": "5.0",
        },
    },
    "host": "https://10.0.0.1:443",
    "matched-at": "https://10.0.0.1:443/",
}

LOW_FINDING_JSON = {
    "template-id": "robots-txt",
    "templateID": "robots-txt",
    "info": {
        "name": "Robots.txt File",
        "severity": "low",
        "description": "Robots.txt file was found.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Robots-Tag",
    },
    "host": "https://10.0.0.1",
    "matched-at": "https://10.0.0.1/robots.txt",
}


# ── Helpers ─────────────────────────────────────────────────────


def _make_async_bytes_iter(lines: list[bytes]) -> AsyncMock:
    """Build an AsyncMock for ``proc.stdout.readline`` that yields *lines*
    then returns ``b''`` to signal EOF.
    """
    readline = AsyncMock()
    readline.side_effect = [*lines, b""]
    return readline


def _make_mock_process(
    stdout_lines: list[bytes] | None = None,
    stderr_bytes: bytes = b"",
    returncode: int = 0,
) -> MagicMock:
    """Build a mock subprocess.Process with async stdout / stderr readers."""
    proc = MagicMock()
    proc.stdout = MagicMock()
    proc.stdout.readline = _make_async_bytes_iter(stdout_lines or [])
    proc.stderr = MagicMock()
    proc.stderr.read = AsyncMock(return_value=stderr_bytes)
    proc.wait = AsyncMock()
    proc.communicate = AsyncMock(
        return_value=(b"" if not stdout_lines else b"\n".join(stdout_lines), stderr_bytes),
    )
    proc.returncode = returncode
    return proc


# ── Dataclass tests ────────────────────────────────────────────


class TestNucleiFindingDefaults:
    """Tests des valeurs par défaut de NucleiFinding."""

    def test_minimal_construction(self) -> None:
        """NucleiFinding avec uniquement les champs obligatoires."""
        f = NucleiFinding(
            template_id="test-template",
            name="Test",
            severity="info",
            host="http://example.com",
            matched_at="http://example.com/",
        )
        assert f.template_id == "test-template"
        assert f.name == "Test"
        assert f.severity == "info"
        assert f.host == "http://example.com"
        assert f.matched_at == "http://example.com/"
        assert f.description == ""
        assert f.cvss_score is None
        assert f.cve_ids == []
        assert f.reference_urls == []
        assert f.extracted_results == []

    def test_all_fields_filled(self) -> None:
        """NucleiFinding avec tous les champs renseignés."""
        f = NucleiFinding(
            template_id="CVE-2023-22515",
            name="Confluence RCE",
            severity="critical",
            host="https://10.0.0.1:8090",
            matched_at="https://10.0.0.1:8090/setup",
            description="Broken access control",
            cvss_score=9.8,
            cve_ids=["CVE-2023-22515"],
            reference_urls=["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
            extracted_results=["curl: some curl command"],
        )
        assert f.cvss_score == 9.8
        assert f.cve_ids == ["CVE-2023-22515"]
        assert f.reference_urls == [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-22515",
        ]
        assert f.extracted_results == ["curl: some curl command"]


# ── _parse_json_line tests ─────────────────────────────────────


class TestParseJsonLine:
    """Tests unitaires de NucleiScanner._parse_json_line."""

    def test_parse_simple_finding(self) -> None:
        """Parse une ligne JSON simple."""
        scanner = NucleiScanner()
        line = json.dumps(SIMPLE_FINDING_JSON)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.template_id == "tomcat-detect"
        assert f.name == "Apache Tomcat Detection"
        assert f.severity == "info"
        assert f.host == "https://10.0.0.1:8080"
        assert f.matched_at == "https://10.0.0.1:8080/"
        assert f.description == "Apache Tomcat server was detected."
        assert f.cvss_score is None
        assert f.cve_ids == []
        # extracted-results includes matcher-name + extracted-results + curl-command
        assert "matcher: tomcat-server-header" in f.extracted_results
        assert "Apache-Coyote/1.1" in f.extracted_results
        assert "curl:" in f.extracted_results[2]

    def test_parse_cve_finding(self) -> None:
        """Parse une ligne JSON avec des informations CVE complètes."""
        scanner = NucleiScanner()
        line = json.dumps(CVE_FINDING_JSON)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.template_id == "CVE-2023-22515"
        assert f.name == "Confluence Data Center & Server - Privilege Escalation"
        assert f.severity == "critical"
        assert f.host == "https://10.0.0.1:8090"
        assert f.matched_at == "https://10.0.0.1:8090/setup"
        assert f.cvss_score == 9.8
        assert f.cve_ids == ["CVE-2023-22515"]
        assert len(f.reference_urls) == 2
        assert "nvd.nist.gov" in f.reference_urls[0]
        assert "confluence.atlassian.com" in f.reference_urls[1]
        assert "matcher: confluence-setup-page" in f.extracted_results
        assert any("curl:" in r for r in f.extracted_results)

    def test_parse_line_with_cvss_string(self) -> None:
        r"""CVSS score sous forme de chaîne (ex: \"5.0\") est converti en float."""
        scanner = NucleiScanner()
        line = json.dumps(MEDIUM_FINDING_JSON)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.cvss_score == 5.0
        assert isinstance(f.cvss_score, float)

    def test_parse_line_single_reference_string(self) -> None:
        """Reference sous forme de chaîne unique est convertie en liste."""
        scanner = NucleiScanner()
        line = json.dumps(LOW_FINDING_JSON)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert len(f.reference_urls) == 1
        assert "developer.mozilla.org" in f.reference_urls[0]

    def test_parse_invalid_json(self) -> None:
        """Une ligne JSON invalide retourne None (l'exception est loggée)."""
        scanner = NucleiScanner()
        f = scanner._parse_json_line("{not valid json}")
        assert f is None

    def test_parse_empty_line(self) -> None:
        """Une ligne vide retourne None."""
        scanner = NucleiScanner()
        f = scanner._parse_json_line("")
        assert f is None

    def test_parse_minimal_fields(self) -> None:
        """Ligne JSON avec seulement les champs minimaux."""
        scanner = NucleiScanner()
        data = {"template-id": "minimal", "info": {"name": "Minimal"}}
        line = json.dumps(data)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.template_id == "minimal"
        assert f.name == "Minimal"
        assert f.severity == "info"  # default
        assert f.host == ""  # no host key
        assert f.matched_at == ""

    def test_parse_uses_templateID_fallback(self) -> None:
        """Utilise 'templateID' si 'template-id' est absent."""
        scanner = NucleiScanner()
        data = {
            "templateID": "fallback-id",
            "info": {"name": "Fallback", "severity": "high"},
            "host": "http://target",
            "matched-at": "http://target/",
        }
        line = json.dumps(data)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.template_id == "fallback-id"

    def test_parse_uses_matched_at_field_name(self) -> None:
        """Utilise 'matched_at' (underscore) si 'matched-at' est absent."""
        scanner = NucleiScanner()
        data = {
            "template-id": "t1",
            "info": {"name": "T1", "severity": "medium"},
            "host": "http://target",
            "matched_at": "http://target/path",
        }
        line = json.dumps(data)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.matched_at == "http://target/path"

    def test_parse_single_cve_id_string(self) -> None:
        """cve-id peut être une chaîne unique au lieu d'une liste."""
        scanner = NucleiScanner()
        data = {
            "template-id": "cve-test",
            "info": {
                "name": "CVE Test",
                "severity": "high",
                "classification": {"cve-id": "CVE-2024-0001"},
            },
            "host": "http://target",
            "matched-at": "http://target/",
        }
        line = json.dumps(data)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.cve_ids == ["CVE-2024-0001"]

    def test_parse_without_extracted_results(self) -> None:
        """Ligne sans extracted-results ni curl-command."""
        scanner = NucleiScanner()
        data = {
            "template-id": "t2",
            "info": {"name": "T2", "severity": "low"},
            "host": "http://target",
            "matched-at": "http://target/",
        }
        line = json.dumps(data)
        f = scanner._parse_json_line(line)
        assert f is not None
        assert f.extracted_results == []


# ── check_installed tests ──────────────────────────────────────


class TestCheckInstalled:
    """Tests de NucleiScanner.check_installed."""

    @pytest.mark.asyncio
    async def test_detected(self) -> None:
        """check_installed retourne True quand nuclei est dans le PATH."""
        scanner = NucleiScanner()
        with patch("shutil.which", return_value="/usr/local/bin/nuclei") as mock_which:
            result = await scanner.check_installed()
            assert result is True
            assert scanner._binary == "/usr/local/bin/nuclei"
            assert scanner._available is True
            mock_which.assert_called_once_with("nuclei")

    @pytest.mark.asyncio
    async def test_not_detected(self) -> None:
        """check_installed retourne False quand nuclei est introuvable."""
        scanner = NucleiScanner()
        with patch("shutil.which", return_value=None):
            result = await scanner.check_installed()
            assert result is False
            assert scanner._binary is None
            assert scanner._available is False

    @pytest.mark.asyncio
    async def test_caches_result(self) -> None:
        """check_installed met en cache le résultat et ne rappelle pas shutil."""
        scanner = NucleiScanner()
        scanner._available = True
        scanner._binary = "/custom/path/nuclei"
        with patch("shutil.which") as mock_which:
            result = await scanner.check_installed()
            assert result is True
            mock_which.assert_not_called()


# ── scan tests ──────────────────────────────────────────────────


class TestScan:
    """Tests de NucleiScanner.scan — mock de subprocess."""

    @pytest.fixture
    def scanner(self):
        """Fixture: NucleiScanner avec check_installed déjà OK."""
        s = NucleiScanner()
        s._available = True
        s._binary = "/usr/local/bin/nuclei"
        return s

    @pytest.mark.asyncio
    async def test_scan_found_findings(self, scanner) -> None:
        """Scan retourne une liste de findings pour une sortie JSON normale."""
        lines = [
            json.dumps(SIMPLE_FINDING_JSON).encode(),
            json.dumps(CVE_FINDING_JSON).encode(),
        ]
        mock_proc = _make_mock_process(stdout_lines=lines)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await scanner.scan("https://10.0.0.1")

        assert len(findings) == 2
        assert findings[0].template_id == "tomcat-detect"
        assert findings[1].template_id == "CVE-2023-22515"
        assert findings[1].severity == "critical"

    @pytest.mark.asyncio
    async def test_scan_empty_results(self, scanner) -> None:
        """Scan retourne une liste vide quand nuclei ne trouve rien."""
        mock_proc = _make_mock_process(stdout_lines=[])

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await scanner.scan("https://10.0.0.1")

        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_not_installed(self) -> None:
        """Scan lève NucleiNotFoundError quand nuclei n'est pas installé."""
        scanner = NucleiScanner()
        scanner._available = False
        scanner._binary = None
        with patch("shutil.which", return_value=None):
            with pytest.raises(NucleiNotFoundError) as excinfo:
                await scanner.scan("https://10.0.0.1")
            assert "nuclei" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_scan_timeout(self, scanner) -> None:
        """Scan lève NucleiTimeoutError quand le timeout est dépassé."""
        mock_proc = _make_mock_process(
            stdout_lines=[b"stuck line\n"],
            stderr_bytes=b"",
        )
        # Make readline hang forever by returning data indefinitely
        mock_proc.stdout.readline.side_effect = [b"data\n"] * 100

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch("asyncio.wait_for") as mock_wait_for:
                mock_wait_for.side_effect = TimeoutError()
                with pytest.raises(NucleiTimeoutError) as excinfo:
                    await scanner.scan("https://10.0.0.1", timeout=1)
                assert "10.0.0.1" in str(excinfo.value)
                assert "1" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_severity_filter(self, scanner) -> None:
        """Scan filtre les résultats par sévérité côté client."""
        lines = [
            json.dumps(SIMPLE_FINDING_JSON).encode(),  # severity: info
            json.dumps(CVE_FINDING_JSON).encode(),  # severity: critical
            json.dumps(MEDIUM_FINDING_JSON).encode(),  # severity: medium
        ]
        mock_proc = _make_mock_process(stdout_lines=lines)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await scanner.scan(
                "https://10.0.0.1",
                severity=["critical", "high"],
            )

        assert len(findings) == 1
        assert findings[0].template_id == "CVE-2023-22515"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_severity_filter_multiple_values(self, scanner) -> None:
        """Scan avec plusieurs sévérités valides."""
        lines = [
            json.dumps(SIMPLE_FINDING_JSON).encode(),  # info
            json.dumps(CVE_FINDING_JSON).encode(),  # critical
            json.dumps(MEDIUM_FINDING_JSON).encode(),  # medium
        ]
        mock_proc = _make_mock_process(stdout_lines=lines)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await scanner.scan(
                "https://10.0.0.1",
                severity=["critical", "medium", "low"],
            )

        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert severities == {"critical", "medium"}

    @pytest.mark.asyncio
    async def test_scan_passes_correct_args(self, scanner) -> None:
        """Scan construit les bons arguments pour le sous-processus."""
        mock_proc = _make_mock_process(stdout_lines=[])

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await scanner.scan(
                "https://10.0.0.1",
                templates=["cves/", "misconfiguration/"],
                severity=["critical"],
            )

        mock_exec.assert_called_once()
        args = mock_exec.call_args[0]
        assert "/usr/local/bin/nuclei" in args[0]
        assert "-json" in args
        assert "-silent" in args
        assert "-t" in args
        assert "cves/" in args
        assert "misconfiguration/" in args
        assert "-s" in args
        assert "critical" in args
        assert "-u" in args
        assert "https://10.0.0.1" in args

    @pytest.mark.asyncio
    async def test_scan_passes_highest_severity(self, scanner) -> None:
        """Scan passe la sévérité la plus élevée à nuclei."""
        mock_proc = _make_mock_process(stdout_lines=[])

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await scanner.scan(
                "https://10.0.0.1",
                severity=["info", "low", "critical", "medium"],
            )

        args = mock_exec.call_args[0]
        crit_idx = args.index("-s")
        assert args[crit_idx + 1] == "critical"

    @pytest.mark.asyncio
    async def test_scan_default_template(self, scanner) -> None:
        """Scan utilise 'cves/' comme template par défaut."""
        mock_proc = _make_mock_process(stdout_lines=[])

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            await scanner.scan("https://10.0.0.1")

        args = mock_exec.call_args[0]
        t_idx = args.index("-t")
        assert args[t_idx + 1] == "cves/"

    @pytest.mark.asyncio
    async def test_scan_nonzero_returncode(self, scanner) -> None:
        """Scan gère les sorties non-nulles sans planter."""
        lines = [json.dumps(SIMPLE_FINDING_JSON).encode()]
        mock_proc = _make_mock_process(stdout_lines=lines, returncode=1)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await scanner.scan("https://10.0.0.1")

        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_scan_skips_bad_json_lines(self, scanner) -> None:
        """Scan ignore les lignes JSON invalides et continue."""
        lines = [
            b"{invalid}\n",
            json.dumps(SIMPLE_FINDING_JSON).encode(),
            b"not json at all\n",
            json.dumps(CVE_FINDING_JSON).encode(),
        ]
        mock_proc = _make_mock_process(stdout_lines=lines)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            findings = await scanner.scan("https://10.0.0.1")

        assert len(findings) == 2


# ── install_templates tests ────────────────────────────────────


class TestInstallTemplates:
    """Tests de NucleiScanner.install_templates."""

    @pytest.mark.asyncio
    async def test_install_templates_success(self) -> None:
        """install_templates appelle nuclei -update-templates avec succès."""
        mock_proc = _make_mock_process(
            stdout_lines=[b"Templates updated successfully\n"],
            returncode=0,
        )

        with patch("shutil.which", return_value="/usr/local/bin/nuclei"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
                await NucleiScanner.install_templates()

        mock_exec.assert_called_once_with(
            "/usr/local/bin/nuclei",
            "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    @pytest.mark.asyncio
    async def test_install_templates_not_installed(self) -> None:
        """install_templates lève NucleiNotFoundError si nuclei est absent."""
        with patch("shutil.which", return_value=None), pytest.raises(NucleiNotFoundError):
            await NucleiScanner.install_templates()

    @pytest.mark.asyncio
    async def test_install_templates_failure_logged(self) -> None:
        """install_templates ne lève pas d'exception en cas d'échec (log seulement)."""
        mock_proc = _make_mock_process(
            stdout_lines=[b""],
            stderr_bytes=b"connection error",
            returncode=1,
        )

        with patch("shutil.which", return_value="/usr/local/bin/nuclei"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                # Should not raise
                await NucleiScanner.install_templates()


# ── update_templates tests ────────────────────────────────────


class TestUpdateTemplates:
    """Tests de NucleiScanner.update_templates (alias)."""

    @pytest.mark.asyncio
    async def test_update_templates_success(self) -> None:
        """update_templates appelle nuclei -update-templates avec succès."""
        mock_proc = _make_mock_process(
            stdout_lines=[b"Templates updated successfully\n"],
            returncode=0,
        )

        with patch("shutil.which", return_value="/usr/local/bin/nuclei"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
                await NucleiScanner.update_templates()

        mock_exec.assert_called_once_with(
            "/usr/local/bin/nuclei",
            "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    @pytest.mark.asyncio
    async def test_update_templates_not_installed(self) -> None:
        """update_templates lève NucleiNotFoundError si nuclei est absent."""
        with patch("shutil.which", return_value=None), pytest.raises(NucleiNotFoundError):
            await NucleiScanner.update_templates()


# ── check_templates tests ─────────────────────────────────────


class TestCheckTemplates:
    """Tests de NucleiScanner.check_templates."""

    @pytest.mark.asyncio
    async def test_templates_found(self, tmp_path) -> None:
        """check_templates retourne True quand les templates existent."""
        # Créer un répertoire de templates factice avec des fichiers .yaml
        templates_dir = tmp_path / ".local" / "nuclei-templates"
        templates_dir.mkdir(parents=True)
        (templates_dir / "cves").mkdir()
        (templates_dir / "cves" / "test-cve.yaml").write_text("id: test\n")

        scanner = NucleiScanner()
        with patch("navmax.scanner.nuclei_scanner._DEFAULT_TEMPLATES_DIR", templates_dir):
            result = await scanner.check_templates()
            assert result is True

    @pytest.mark.asyncio
    async def test_templates_not_found(self, tmp_path) -> None:
        """check_templates retourne False quand le répertoire n'existe pas."""
        inexistant = tmp_path / "nonexistent" / "nuclei-templates"

        scanner = NucleiScanner()
        with patch("navmax.scanner.nuclei_scanner._DEFAULT_TEMPLATES_DIR", inexistant):
            result = await scanner.check_templates()
            assert result is False

    @pytest.mark.asyncio
    async def test_templates_empty_directory(self, tmp_path) -> None:
        """check_templates retourne False quand le répertoire est vide."""
        empty_dir = tmp_path / "empty" / "nuclei-templates"
        empty_dir.mkdir(parents=True)

        scanner = NucleiScanner()
        with patch("navmax.scanner.nuclei_scanner._DEFAULT_TEMPLATES_DIR", empty_dir):
            result = await scanner.check_templates()
            assert result is False

    @pytest.mark.asyncio
    async def test_templates_no_yaml_files(self, tmp_path) -> None:
        """check_templates retourne False quand il n'y a pas de fichiers .yaml."""
        no_yaml_dir = tmp_path / "noyaml" / "nuclei-templates"
        no_yaml_dir.mkdir(parents=True)
        (no_yaml_dir / "cves").mkdir()
        (no_yaml_dir / "cves" / "readme.txt").write_text("not a template")

        scanner = NucleiScanner()
        with patch("navmax.scanner.nuclei_scanner._DEFAULT_TEMPLATES_DIR", no_yaml_dir):
            result = await scanner.check_templates()
            assert result is False
