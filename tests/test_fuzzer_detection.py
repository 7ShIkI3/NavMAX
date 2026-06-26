"""Tests pour la détection d'anomalies command_injection du fuzzer.

Teste les patterns regex ajoutés dans navmax/proxy/fuzzer.py::_detect_anomalies()
pour détecter les preuves d'exécution de commande dans les réponses HTTP.

Utilise httpx.Response mockées pour simuler des réelles réponses de serveur.
"""

from unittest.mock import MagicMock

import httpx
import pytest

from navmax.proxy.fuzzer import Fuzzer, FuzzResult

# ---------------------------------------------------------------------------
# Helpers — construire une réponse httpx mockée
# ---------------------------------------------------------------------------


def _make_response(text: str, status_code: int = 200) -> httpx.Response:
    """Crée une httpx.Response mockée avec le contenu texte donné."""
    mock = MagicMock(spec=httpx.Response)
    mock.status_code = status_code
    mock.text = text
    mock.content = text.encode("utf-8")
    mock.headers = {"Content-Type": "text/html"}
    return mock


def _make_result(
    payload: str,
    category: str = "command_injection",
    length_diff: int = 0,
    status: int = 200,
) -> FuzzResult:
    """Crée un FuzzResult avec les valeurs de test."""
    return FuzzResult(
        url="http://test.com/page?id=1",
        injection_point="parameter",
        parameter_name="id",
        payload=payload,
        payload_category=category,
        original_status=200,
        fuzz_status=status,
        response_length_diff=length_diff,
        response_time_diff_ms=10.0,
    )


@pytest.fixture
def fuzzer() -> Fuzzer:
    """Fixture : instance Fuzzer avec config minimale."""
    return Fuzzer(timeout=1.0, concurrency=1, categories=["command_injection"])


# ===========================================================================
# Tests de détection par regex — preuves d'exécution de commande
# ===========================================================================


class TestDetectCommandExecutionEvidence:
    """Vérifie que _detect_anomalies détecte les patterns de sortie de commandes."""

    def detect(self, fuzzer: Fuzzer, result: FuzzResult, resp_text: str) -> list[str]:
        """Appelle _detect_anomalies et retourne les anomalies."""
        resp = _make_response(resp_text)
        baseline = {"status": 200, "length": len(resp_text) - 100, "headers": {}}
        return fuzzer._detect_anomalies(result, resp, baseline)

    # --- Patterns Unix ---

    def test_uid_pattern(self, fuzzer: Fuzzer) -> None:
        """'uid=1000' dans la réponse → alerte command_injection."""
        result = _make_result("; id")
        anomalies = self.detect(
            fuzzer, result, "uid=1000(alice) gid=1000(alice) groups=1000(alice)",
        )
        assert any("Exécution de commande" in a for a in anomalies), (
            f"uid=... devrait être détecté, anomalies={anomalies}"
        )

    def test_root_passwd_pattern(self, fuzzer: Fuzzer) -> None:
        """'root:...:0:0:' dans la réponse → alerte."""
        result = _make_result("| cat /etc/passwd")
        passwd_line = "root:x:0:0:root:/root:/bin/bash"
        anomalies = self.detect(fuzzer, result, passwd_line)
        assert any("Exécution de commande" in a for a in anomalies)

    def test_bin_passwd_pattern(self, fuzzer: Fuzzer) -> None:
        """'bin:...:1:1:' dans la réponse → alerte."""
        result = _make_result("`cat /etc/passwd`")
        anomalies = self.detect(fuzzer, result, "bin:x:1:1:bin:/bin:/sbin/nologin")
        assert any("Exécution de commande" in a for a in anomalies)

    def test_total_ls_pattern(self, fuzzer: Fuzzer) -> None:
        """'total 42' dans la réponse → alerte."""
        result = _make_result("; ls -la")
        anomalies = self.detect(
            fuzzer, result, "total 42\ndrwxr-xr-x 2 root root 4096 Jan 1 00:00 .",
        )
        assert any("Exécution de commande" in a for a in anomalies)

    def test_unix_permissions_pattern(self, fuzzer: Fuzzer) -> None:
        """Permissions Unix (rwxr-xr-x) dans la réponse → alerte."""
        result = _make_result("; ls -la")
        anomalies = self.detect(
            fuzzer, result, "drwxr-xr-x 2 alice staff 4096 Mar 15 14:30 Documents",
        )
        assert any("Exécution de commande" in a for a in anomalies)

    def test_ls_date_pattern(self, fuzzer: Fuzzer) -> None:
        """Date style ls (Mar 15 14:30) dans la réponse → alerte."""
        result = _make_result("| ls")
        anomalies = self.detect(fuzzer, result, "-rw-r--r-- 1 root root 1234 Mar 15 14:30 file.txt")
        assert any("Exécution de commande" in a for a in anomalies)

    # --- Patterns Windows ---

    def test_volume_serial_number(self, fuzzer: Fuzzer) -> None:
        """'Volume Serial Number' dans la réponse → alerte."""
        result = _make_result("&& dir C:\\")
        anomalies = self.detect(
            fuzzer,
            result,
            " Volume in drive C has no label\n Volume Serial Number is 1234-ABCD\n Directory of C:\\",
        )
        assert any("Exécution de commande" in a for a in anomalies)

    def test_directory_of_pattern(self, fuzzer: Fuzzer) -> None:
        """'Directory of ' dans la réponse → alerte."""
        result = _make_result("| dir")
        anomalies = self.detect(fuzzer, result, " Directory of C:\\Users\\Admin\n...")
        assert any("Exécution de commande" in a for a in anomalies)

    # --- Pas de faux positif pour des réponses normales ---

    def test_no_false_positive_html(self, fuzzer: Fuzzer) -> None:
        """Réponse HTML normale sans pattern cmd → pas d'alerte."""
        result = _make_result("; ls")
        html = """<html><body><h1>Welcome</h1><p>Page not found</p></body></html>"""
        anomalies = self.detect(fuzzer, result, html)
        cmd_anomalies = [a for a in anomalies if "commande" in a.lower() or "pattern" in a.lower()]
        assert len(cmd_anomalies) == 0, (
            f"HTML normal ne devrait pas déclencher cmd_detection, {cmd_anomalies=}"
        )

    def test_no_false_positive_json(self, fuzzer: Fuzzer) -> None:
        """Réponse JSON normale → pas d'alerte."""
        result = _make_result("; id")
        json_resp = '{"status":"ok","data":{"id":42,"name":"test"}}'
        anomalies = self.detect(fuzzer, result, json_resp)
        cmd_anomalies = [a for a in anomalies if "commande" in a.lower()]
        assert len(cmd_anomalies) == 0

    def test_no_false_positive_error_page(self, fuzzer: Fuzzer) -> None:
        """Page d'erreur standard → pas d'alerte."""
        result = _make_result("| whoami")
        error = "<html><body><h1>500 Internal Server Error</h1></body></html>"
        anomalies = self.detect(fuzzer, result, error)
        cmd_anomalies = [a for a in anomalies if "commande" in a.lower()]
        assert len(cmd_anomalies) == 0


# ===========================================================================
# Tests de détection par Content-Length
# ===========================================================================


class TestDetectContentLengthDiff:
    """Vérifie la détection via la différence de taille de réponse."""

    def detect(self, fuzzer: Fuzzer, result: FuzzResult) -> list[str]:
        resp = _make_response("a" * 500)
        baseline = {"status": 200, "length": 200, "headers": {}}
        return fuzzer._detect_anomalies(result, resp, baseline)

    def test_diff_gt_100_detected(self, fuzzer: Fuzzer) -> None:
        """Différence > 100 octets pour command_injection → alerte."""
        result = _make_result("; id", length_diff=250)
        anomalies = self.detect(fuzzer, result)
        assert any("Variation de taille suspecte" in a for a in anomalies), (
            f"length_diff=250 devrait être détecté, {anomalies=}"
        )

    def test_diff_lt_100_not_detected(self, fuzzer: Fuzzer) -> None:
        """Différence ≤ 100 octets → pas d'alerte."""
        result = _make_result("; id", length_diff=50)
        anomalies = self.detect(fuzzer, result)
        taille_anomalies = [a for a in anomalies if "taille" in a.lower()]
        assert len(taille_anomalies) == 0, (
            f"length_diff=50 ne devrait pas déclencher, {taille_anomalies=}"
        )

    def test_diff_negative_gt_100(self, fuzzer: Fuzzer) -> None:
        """Différence négative (réponse plus petite) > 100 → alerte."""
        result = _make_result("; id", length_diff=-200)
        anomalies = self.detect(fuzzer, result)
        assert any("Variation de taille suspecte" in a for a in anomalies)


# ===========================================================================
# Tests de non-régression
# ===========================================================================


class TestNoRegression:
    """Les comportements existants ne sont pas cassés."""

    def test_xss_still_detected(self, fuzzer: Fuzzer) -> None:
        """XSS reflection est toujours détectée."""
        result = _make_result(
            "<script>alert(1)</script>",
            category="xss",
        )
        resp = _make_response("Reflected: <script>alert(1)</script>")
        baseline = {"status": 200, "length": 50, "headers": {}}
        anomalies = fuzzer._detect_anomalies(result, resp, baseline)
        assert any("XSS" in a for a in anomalies)

    def test_sql_still_detected(self, fuzzer: Fuzzer) -> None:
        """SQL error est toujours détectée."""
        result = _make_result("' OR 1=1--", category="sqli")
        resp = _make_response("You have an error in your SQL syntax")
        baseline = {"status": 200, "length": 100, "headers": {}}
        anomalies = fuzzer._detect_anomalies(result, resp, baseline)
        assert any("SQL" in a for a in anomalies)

    def test_http_500_still_detected(self, fuzzer: Fuzzer) -> None:
        """HTTP 500 est toujours détecté."""
        result = _make_result("test", status=500)
        resp = _make_response("Internal Server Error", status_code=500)
        baseline = {"status": 200, "length": 50, "headers": {}}
        anomalies = fuzzer._detect_anomalies(result, resp, baseline)
        assert any("Erreur serveur" in a for a in anomalies)

    def test_time_anomaly_still_detected(self, fuzzer: Fuzzer) -> None:
        """Temps de réponse anormal est toujours détecté."""
        result = _make_result("test")
        result.response_time_diff_ms = 5000.0
        resp = _make_response("slow response")
        baseline = {"status": 200, "length": 50, "headers": {}}
        anomalies = fuzzer._detect_anomalies(result, resp, baseline)
        assert any("Temps de réponse anormal" in a for a in anomalies)

    def test_length_anomaly_still_detected(self, fuzzer: Fuzzer) -> None:
        """Taille anormale (diff > 5000) est toujours détectée."""
        result = _make_result("test", length_diff=6000)
        resp = _make_response("x" * 6000)
        baseline = {"status": 200, "length": 50, "headers": {}}
        anomalies = fuzzer._detect_anomalies(result, resp, baseline)
        assert any("Taille de réponse anormale" in a for a in anomalies)


# ===========================================================================
# Tests que la détection est spécifique à command_injection
# ===========================================================================


class TestCategorySpecificity:
    """La détection command_injection ne doit pas s'activer pour d'autres catégories."""

    def detect(self, fuzzer: Fuzzer, result: FuzzResult, resp_text: str) -> list[str]:
        resp = _make_response(resp_text)
        baseline = {"status": 200, "length": 50, "headers": {}}
        return fuzzer._detect_anomalies(result, resp, baseline)

    def test_not_for_xss(self, fuzzer: Fuzzer) -> None:
        """uid=... dans XSS ne déclenche PAS cmd_injection."""
        result = _make_result("<script>alert(1)</script>", category="xss")
        anomalies = self.detect(fuzzer, result, "uid=1000(alice) gid=1000(alice)")
        cmd_anomalies = [a for a in anomalies if "commande" in a.lower()]
        assert len(cmd_anomalies) == 0

    def test_not_for_sqli(self, fuzzer: Fuzzer) -> None:
        """root:... dans SQLi ne déclenche PAS cmd_injection."""
        result = _make_result("' OR 1=1--", category="sqli")
        anomalies = self.detect(fuzzer, result, "root:x:0:0:root:/root:/bin/bash")
        cmd_anomalies = [a for a in anomalies if "commande" in a.lower()]
        assert len(cmd_anomalies) == 0

    def test_not_for_path_traversal(self, fuzzer: Fuzzer) -> None:
        """Volume Serial Number dans path_traversal ne déclenche PAS."""
        result = _make_result("../../../etc/passwd", category="path_traversal")
        anomalies = self.detect(fuzzer, result, "Volume Serial Number is 1234-ABCD")
        cmd_anomalies = [a for a in anomalies if "commande" in a.lower()]
        assert len(cmd_anomalies) == 0


# ===========================================================================
# Tests des payloads enrichis
# ===========================================================================


class TestCommandInjectionPayloads:
    """Vérifie que les nouveaux payloads sont présents dans FUZZ_PAYLOADS."""

    def test_basic_separators_present(self) -> None:
        from navmax.proxy.fuzzer import FUZZ_PAYLOADS

        cmd = FUZZ_PAYLOADS.get("command_injection", [])
        assert any("; id" in p for p in cmd), "; id manquant"
        assert any("& whoami" in p for p in cmd), "& whoami manquant"
        assert any("|| whoami" in p for p in cmd), "|| whoami manquant"
        assert any("`ls`" in p for p in cmd), "`ls` manquant"
        assert any("&& whoami" in p for p in cmd), "&& whoami manquant"

    def test_windows_commands_present(self) -> None:
        from navmax.proxy.fuzzer import FUZZ_PAYLOADS

        cmd = FUZZ_PAYLOADS.get("command_injection", [])
        assert any("type" in p and "hosts" in p for p in cmd), "type C:\\...\\hosts manquant"

    def test_url_encoded_payloads_present(self) -> None:
        from navmax.proxy.fuzzer import FUZZ_PAYLOADS

        cmd = FUZZ_PAYLOADS.get("command_injection", [])
        assert any("%3B%20id" in p for p in cmd), "URL encodé %3B%20id manquant"
        assert any("%7C%20id" in p for p in cmd), "URL encodé %7C%20id manquant"
        assert any("%253B%2520id" in p for p in cmd), "Double encodé %253B%2520id manquant"
        assert any("%257C%2520id" in p for p in cmd), "Double encodé %257C%2520id manquant"

    def test_unix_extra_commands_present(self) -> None:
        from navmax.proxy.fuzzer import FUZZ_PAYLOADS

        cmd = FUZZ_PAYLOADS.get("command_injection", [])
        assert any("cat /etc/hosts" in p for p in cmd), "cat /etc/hosts manquant"
        assert any("$(id)" in p for p in cmd), "$(id) manquant"


class TestPredefinedCommandInjectionPayloads:
    """Vérifie les payloads PREDEFINED_PAYLOADS dans intruder.py."""

    def test_new_payloads_present(self) -> None:
        from navmax.proxy.intruder import PREDEFINED_PAYLOADS

        cmd = PREDEFINED_PAYLOADS.get("command_injection", [])
        assert any("nslookup" in p for p in cmd), "nslookup manquant"
        assert any("type C:" in p for p in cmd), "type C: manquant"
        assert any("%3Bid" in p for p in cmd), "%3Bid manquant"
        assert any("%253Bid" in p for p in cmd), "%253Bid manquant"
        assert any("cat /etc/hosts" in p for p in cmd), "cat /etc/hosts manquant"

    def test_existing_still_present(self) -> None:
        from navmax.proxy.intruder import PREDEFINED_PAYLOADS

        cmd = PREDEFINED_PAYLOADS.get("command_injection", [])
        assert any("ls" in p for p in cmd)
        assert any("id" in p for p in cmd)
        assert any("whoami" in p for p in cmd)
