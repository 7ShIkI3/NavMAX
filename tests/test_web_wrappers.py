"""Tests pour les wrappers web — SQLMap et FFUF.

Teste les modèles de données, la construction des arguments,
et le parsing des sorties (sans exécuter les binaires réels).
"""

import json
import tempfile
from pathlib import Path

import pytest

from navmax.web.ffuf_wrapper import (
    FfufEntry,
    FfufFilterOption,
    FfufInput,
    FfufResult,
    FfufWrapper,
    extract_domain,
)
from navmax.web.sqlmap_wrapper import (
    SQLMapWrapper,
    SqlmapResult,
    SqlmapStatus,
    WHITELISTED_OPTIONS,
)


# ═══════════════════════════════════════════════════════════════
# SQLMap Wrapper
# ═══════════════════════════════════════════════════════════════


class TestSqlmapModels:
    """Tests des modèles de données sqlmap."""

    def test_sqlmap_result_defaults(self) -> None:
        result = SqlmapResult(url="http://test.com/page?id=1")
        assert result.url == "http://test.com/page?id=1"
        assert result.vulnerable is False
        assert result.technique == ""
        assert result.error is None

    def test_sqlmap_result_vulnerable(self) -> None:
        result = SqlmapResult(
            url="http://test.com/page?id=1",
            vulnerable=True,
            technique="B",
            dbms="MySQL",
        )
        assert result.vulnerable is True
        assert result.technique == "B"
        assert result.dbms == "MySQL"

    def test_sqlmap_status_defaults(self) -> None:
        status = SqlmapStatus()
        assert status.running is False
        assert status.exit_code is None
        assert status.error is None


class TestSQLMapWrapperArgs:
    """Teste la construction des arguments sqlmap."""

    def test_available_property(self) -> None:
        """Vérifie que available retourne False sans sqlmap installé."""
        wrapper = SQLMapWrapper(sqlmap_path="/nonexistent/sqlmap")
        assert wrapper.available is False

    def test_check_installation(self) -> None:
        wrapper = SQLMapWrapper(sqlmap_path="/nonexistent/sqlmap")
        msg = wrapper.check_installation()
        assert "n'est pas installé" in msg

    def test_whitelisted_options(self) -> None:
        """Vérifie que les options courantes sont whitelistées."""
        essential = {"batch", "random-agent", "threads", "level", "risk", "dbms",
                     "technique", "dump", "tables", "proxy", "cookie", "crawl"}
        for opt in essential:
            assert opt in WHITELISTED_OPTIONS, f"{opt} devrait être whitelisté"


class TestSqlmapParsing:
    """Teste le parsing de la sortie sqlmap simulée."""

    def test_parse_vulnerable_output(self) -> None:
        """Parse une sortie indiquant une injection détectée."""
        wrapper = SQLMapWrapper(sqlmap_path="/nonexistent/sqlmap")
        stdout = """
[INFO] testing connection to the target URL
[INFO] testing if the target URL is stable
[INFO] target URL is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] confirming that GET parameter 'id' is injectable
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 1=1-- -

[INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 7.4, Apache 2.4
back-end DBMS: MySQL >= 5.0
        """
        result = wrapper._parse_output(
            url="http://test.com/page?id=1",
            output_dir="/tmp/fake",
            stdout=stdout,
            stderr="",
        )
        assert result.vulnerable is True
        assert result.technique == "B"
        assert "MySQL" in result.dbms
        assert "1=1" in result.payload

    def test_parse_not_vulnerable(self) -> None:
        """Parse une sortie indiquant l'absence d'injection."""
        wrapper = SQLMapWrapper(sqlmap_path="/nonexistent/sqlmap")
        stdout = """
[INFO] testing connection to the target URL
[INFO] testing if the target URL is stable
[INFO] target URL is stable
[INFO] testing all parameters
[INFO] all tested parameters are not injectable
[INFO] shutting down
        """
        result = wrapper._parse_output(
            url="http://test.com/page?id=1",
            output_dir="/tmp/fake",
            stdout=stdout,
            stderr="",
        )
        assert result.vulnerable is False

    def test_parse_db_extraction(self) -> None:
        """Parse une sortie avec extraction de base de données."""
        wrapper = SQLMapWrapper(sqlmap_path="/nonexistent/sqlmap")
        stdout = """
current database: 'wordpress'
current user: 'root@localhost'
        """
        result = wrapper._parse_output(
            url="http://test.com/page?id=1",
            output_dir="/tmp/fake",
            stdout=stdout,
            stderr="",
        )
        assert result.db == "wordpress"


# ═══════════════════════════════════════════════════════════════
# FFUF Wrapper
# ═══════════════════════════════════════════════════════════════


class TestFfufModels:
    """Tests des modèles de données ffuf."""

    def test_ffuf_entry_defaults(self) -> None:
        entry = FfufEntry(url="http://test.com/admin")
        assert entry.url == "http://test.com/admin"
        assert entry.status == 0
        assert entry.size == 0

    def test_ffuf_entry_full(self) -> None:
        entry = FfufEntry(
            url="http://test.com/admin",
            status=200,
            size=1234,
            words=100,
            lines=20,
        )
        assert entry.status == 200
        assert entry.size == 1234

    def test_ffuf_result_defaults(self) -> None:
        result = FfufResult(url="http://test.com/FUZZ", wordlist="/tmp/wordlist.txt")
        assert result.total_entries == 0
        assert result.error is None

    def test_ffuf_input_defaults(self) -> None:
        inp = FfufInput(url="http://test.com/FUZZ", wordlist="/tmp/words.txt")
        assert inp.filter_codes == ""
        assert inp.options == {}


class TestFfufWrapper:
    """Tests du wrapper ffuf (sans binaire réel)."""

    def test_available_property(self) -> None:
        """Vérifie que available retourne False sans ffuf."""
        wrapper = FfufWrapper(ffuf_path="/nonexistent/ffuf")
        assert wrapper.available is False

    def test_check_installation(self) -> None:
        wrapper = FfufWrapper(ffuf_path="/nonexistent/ffuf")
        msg = wrapper.check_installation()
        assert "n'est pas installé" in msg

    def test_execute_fails_without_binary(self) -> None:
        """Vérifie que _execute retourne une erreur sans ffuf."""
        wrapper = FfufWrapper(ffuf_path="/nonexistent/ffuf")
        inp = FfufInput(url="http://test.com/FUZZ", wordlist="/tmp/words.txt")

        import asyncio
        result = asyncio.run(wrapper._execute(inp))
        assert result.error is not None
        assert "installé" in result.error

    def test_execute_with_missing_wordlist(self) -> None:
        """Vérifie l'erreur si wordlist introuvable."""
        wrapper = FfufWrapper(ffuf_path="ffuf")  # le binaire peut exister
        inp = FfufInput(url="http://test.com/FUZZ", wordlist="/nonexistent/wordlist.txt")

        import asyncio
        result = asyncio.run(wrapper._execute(inp))
        # Soit ffuf n'est pas installé, soit la wordlist manque
        assert result.error is not None


class TestFfufJsonParsing:
    """Teste le parsing de la sortie JSON de ffuf."""

    def test_parse_json_output(self, tmp_path: Path) -> None:
        """Parse un fichier JSON ffuf simulé."""
        wrapper = FfufWrapper(ffuf_path="/nonexistent/ffuf")
        json_path = tmp_path / "ffuf_output.json"

        mock_data = {
            "results": [
                {
                    "url": "http://test.com/admin",
                    "status": 200,
                    "length": 1234,
                    "words": 100,
                    "lines": 20,
                    "content_type": "text/html",
                    "duration": 15.5,
                },
                {
                    "url": "http://test.com/.git/config",
                    "status": 403,
                    "length": 300,
                    "words": 25,
                    "lines": 5,
                    "content_type": "application/octet-stream",
                    "duration": 10.2,
                },
            ]
        }
        json_path.write_text(json.dumps(mock_data))

        result = FfufResult(url="http://test.com/FUZZ", wordlist="/tmp/words.txt")
        parsed = wrapper._parse_json_output(result, str(json_path))

        assert len(parsed.entries) == 2
        assert parsed.entries[0].url == "http://test.com/admin"
        assert parsed.entries[0].status == 200
        assert parsed.entries[1].status == 403
        assert parsed.entries[1].size == 300

    def test_parse_invalid_json(self, tmp_path: Path) -> None:
        """Parse un JSON invalide."""
        wrapper = FfufWrapper(ffuf_path="/nonexistent/ffuf")
        json_path = tmp_path / "bad.json"
        json_path.write_text("not json")

        result = FfufResult(url="http://test.com/FUZZ", wordlist="/tmp/words.txt")
        parsed = wrapper._parse_json_output(result, str(json_path))
        assert parsed.error is not None
        assert "Erreur parsing" in parsed.error

    def test_parse_text_output(self) -> None:
        """Parse une sortie texte ffuf simulée."""
        wrapper = FfufWrapper(ffuf_path="/nonexistent/ffuf")
        text_output = """
        [Status: 200, Size: 1234, Words: 100, Lines: 20] -> http://test.com/admin
        [Status: 301, Size: 0, Words: 1, Lines: 1] -> http://test.com/redirect
        """

        result = FfufResult(url="http://test.com/FUZZ", wordlist="/tmp/words.txt")
        parsed = wrapper._parse_text_output(result, text_output)

        # Vérifier que le parseur texte trouve les entrées
        assert len(parsed.entries) > 0


class TestExtractDomain:
    """Tests de extract_domain."""

    def test_simple_domain(self) -> None:
        assert extract_domain("http://target.com/page") == "target.com"

    def test_subdomain(self) -> None:
        assert extract_domain("http://admin.target.com") == "target.com"

    def test_with_path(self) -> None:
        assert extract_domain("http://test.local/admin") == "test.local"

    def test_https(self) -> None:
        assert extract_domain("https://secure.site.com:443/path") == "site.com"

    def test_ip_address(self) -> None:
        assert extract_domain("http://192.168.1.1:8080") == "192.168.1.1"


class TestFfufFilterOption:
    """Tests de l'enum FfufFilterOption."""

    def test_status_code_option(self) -> None:
        assert FfufFilterOption.STATUS_CODE.value == "fc"

    def test_size_option(self) -> None:
        assert FfufFilterOption.SIZE.value == "fs"

    def test_words_option(self) -> None:
        assert FfufFilterOption.WORDS.value == "fw"

    def test_lines_option(self) -> None:
        assert FfufFilterOption.LINES.value == "fl"
