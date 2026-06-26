"""Tests pour navmax/proxy/intruder.py — Intruder style Burp.

Teste :
- Les dataclasses (IntruderResult, IntruderReport)
- Les payloads prédéfinis (numbers, dates, passwords, sqli, xss, etc.)
- Le parsing des positions
- L'application des payloads aux requêtes
- Les filtres (filter_status, filter_length, grep_match)
- Les modes sniper et cluster_bomb
- L'intégration avec les requêtes HTTP (via httpx mock)
- La fonction utilitaire quick_attack
"""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navmax.proxy.intruder import (
    PREDEFINED_PAYLOADS,
    Intruder,
    IntruderFilters,
    IntruderReport,
    IntruderResult,
    _apply_payload,
    _parse_cookies,
    _parse_position,
    _replace_form_field,
    _set_nested_key,
    quick_attack,
)

# ===========================================================================
# Tests des payloads prédéfinis
# ===========================================================================


class TestPredefinedPayloads:
    """Vérifie que les payloads prédéfinis sont bien définis et non vides."""

    def test_numbers(self) -> None:
        assert "numbers" in PREDEFINED_PAYLOADS
        assert len(PREDEFINED_PAYLOADS["numbers"]) == 100
        assert PREDEFINED_PAYLOADS["numbers"][0] == "1"
        assert PREDEFINED_PAYLOADS["numbers"][99] == "100"

    def test_dates(self) -> None:
        assert "dates" in PREDEFINED_PAYLOADS
        assert len(PREDEFINED_PAYLOADS["dates"]) > 10
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        assert today in PREDEFINED_PAYLOADS["dates"]

    def test_passwords(self) -> None:
        assert "passwords" in PREDEFINED_PAYLOADS
        assert len(PREDEFINED_PAYLOADS["passwords"]) == 100
        assert "password" in PREDEFINED_PAYLOADS["passwords"]
        assert "admin" in PREDEFINED_PAYLOADS["passwords"]
        assert "123456" in PREDEFINED_PAYLOADS["passwords"]

    def test_sqli(self) -> None:
        assert "sqli" in PREDEFINED_PAYLOADS
        assert len(PREDEFINED_PAYLOADS["sqli"]) > 20
        assert any("OR 1=1" in p for p in PREDEFINED_PAYLOADS["sqli"])
        assert any("UNION SELECT" in p for p in PREDEFINED_PAYLOADS["sqli"])
        assert any("SLEEP" in p for p in PREDEFINED_PAYLOADS["sqli"])

    def test_xss(self) -> None:
        assert "xss" in PREDEFINED_PAYLOADS
        assert len(PREDEFINED_PAYLOADS["xss"]) > 10
        assert any("alert(1)" in p for p in PREDEFINED_PAYLOADS["xss"])
        assert any("<script>" in p for p in PREDEFINED_PAYLOADS["xss"])
        assert any("onerror" in p for p in PREDEFINED_PAYLOADS["xss"])

    def test_path_traversal(self) -> None:
        assert "path_traversal" in PREDEFINED_PAYLOADS
        assert any("etc/passwd" in p for p in PREDEFINED_PAYLOADS["path_traversal"])

    def test_command_injection(self) -> None:
        assert "command_injection" in PREDEFINED_PAYLOADS
        assert any("ls" in p for p in PREDEFINED_PAYLOADS["command_injection"])
        assert any("id" in p for p in PREDEFINED_PAYLOADS["command_injection"])

    def test_ssti(self) -> None:
        assert "ssti" in PREDEFINED_PAYLOADS
        assert "{{7*7}}" in PREDEFINED_PAYLOADS["ssti"]


# ===========================================================================
# Tests des dataclasses
# ===========================================================================


class TestIntruderResult:
    """Tests de la dataclass IntruderResult."""

    def test_default_creation(self) -> None:
        result = IntruderResult(
            request_modifie={"method": "GET", "url": "https://example.com"},
            status_code=200,
            response_length=100,
            response_time_ms=50.0,
            payload_position="param:id",
            payload_value="test",
        )
        assert result.status_code == 200
        assert result.response_length == 100
        assert result.response_time_ms == 50.0
        assert result.match is False
        assert result.error is None
        assert result.payload_position == "param:id"
        assert result.payload_value == "test"

    def test_with_match(self) -> None:
        result = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=50,
            response_time_ms=10.0,
            match=True,
            payload_position="header:X-Custom",
            payload_value="<script>alert(1)</script>",
        )
        assert result.match is True

    def test_with_error(self) -> None:
        result = IntruderResult(
            request_modifie={},
            status_code=0,
            response_length=0,
            response_time_ms=5000.0,
            error="Timeout",
            payload_position="raw",
            payload_value="test",
        )
        assert result.error == "Timeout"
        assert result.status_code == 0


class TestIntruderReport:
    """Tests de la dataclass IntruderReport."""

    def test_default_creation(self) -> None:
        report = IntruderReport(
            target_url="https://example.com",
            target_method="GET",
            mode="sniper",
            positions=["param:id"],
            total_requests=5,
        )
        assert report.target_url == "https://example.com"
        assert report.mode == "sniper"
        assert report.total_requests == 5
        assert report.results == []
        assert report.duration_ms == 0.0

    def test_matched_property(self) -> None:
        report = IntruderReport(
            target_url="https://example.com",
            target_method="GET",
            mode="cluster_bomb",
            positions=["param:id", "header:X-Custom"],
            total_requests=3,
        )
        result1 = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=100,
            response_time_ms=10.0,
            match=True,
            payload_position="param:id",
            payload_value="test",
        )
        result2 = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=100,
            response_time_ms=10.0,
            match=False,
            payload_position="param:id",
            payload_value="other",
        )
        report.results = [result1, result2]
        assert len(report.matched) == 1
        assert report.matched[0] is result1

    def test_errors_property(self) -> None:
        report = IntruderReport(
            target_url="https://example.com",
            target_method="GET",
            mode="sniper",
            positions=["param:id"],
            total_requests=2,
        )
        ok = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=100,
            response_time_ms=10.0,
            payload_position="param:id",
            payload_value="ok",
        )
        err = IntruderResult(
            request_modifie={},
            status_code=0,
            response_length=0,
            response_time_ms=5000.0,
            error="Connection refused",
            payload_position="param:id",
            payload_value="bad",
        )
        report.results = [ok, err]
        assert len(report.errors) == 1
        assert report.errors[0] is err

    def test_status_counts(self) -> None:
        report = IntruderReport(
            target_url="https://example.com",
            target_method="GET",
            mode="sniper",
            positions=["param:id"],
            total_requests=4,
        )
        results = [
            IntruderResult(
                request_modifie={},
                status_code=200,
                response_length=100,
                response_time_ms=10.0,
                payload_position="p",
                payload_value="a",
            ),
            IntruderResult(
                request_modifie={},
                status_code=200,
                response_length=100,
                response_time_ms=10.0,
                payload_position="p",
                payload_value="b",
            ),
            IntruderResult(
                request_modifie={},
                status_code=500,
                response_length=100,
                response_time_ms=10.0,
                payload_position="p",
                payload_value="c",
            ),
            IntruderResult(
                request_modifie={},
                status_code=403,
                response_length=100,
                response_time_ms=10.0,
                payload_position="p",
                payload_value="d",
            ),
        ]
        report.results = results
        counts = report.status_counts
        assert counts == {200: 2, 500: 1, 403: 1}


# ===========================================================================
# Tests des filtres
# ===========================================================================


class TestIntruderFilters:
    """Tests des filtres IntruderFilters."""

    def test_no_filters(self) -> None:
        filters = IntruderFilters()
        result = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=500,
            response_time_ms=10.0,
            payload_position="p",
            payload_value="v",
        )
        assert filters.matches(result) is True

    def test_filter_status_match(self) -> None:
        filters = IntruderFilters(filter_status=[200, 404])
        result_200 = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=100,
            response_time_ms=10.0,
            payload_position="p",
            payload_value="v",
        )
        result_500 = IntruderResult(
            request_modifie={},
            status_code=500,
            response_length=100,
            response_time_ms=10.0,
            payload_position="p",
            payload_value="v",
        )
        assert filters.matches(result_200) is True
        assert filters.matches(result_500) is False

    def test_filter_length_match(self) -> None:
        filters = IntruderFilters(filter_length=(100, 500))
        result_small = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=50,
            response_time_ms=10.0,
            payload_position="p",
            payload_value="v",
        )
        result_ok = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=300,
            response_time_ms=10.0,
            payload_position="p",
            payload_value="v",
        )
        result_large = IntruderResult(
            request_modifie={},
            status_code=200,
            response_length=1000,
            response_time_ms=10.0,
            payload_position="p",
            payload_value="v",
        )
        assert filters.matches(result_small) is False
        assert filters.matches(result_ok) is True
        assert filters.matches(result_large) is False


# ===========================================================================
# Tests du parsing des positions
# ===========================================================================


class TestParsePosition:
    """Tests de _parse_position()."""

    def test_header(self) -> None:
        assert _parse_position("header:X-Custom-Header") == ("header", "X-Custom-Header")

    def test_param(self) -> None:
        assert _parse_position("param:id") == ("param", "id")

    def test_body(self) -> None:
        assert _parse_position("body:username") == ("body", "username")

    def test_path(self) -> None:
        assert _parse_position("path:2") == ("path", "2")

    def test_cookie(self) -> None:
        assert _parse_position("cookie:PHPSESSID") == ("cookie", "PHPSESSID")

    def test_raw(self) -> None:
        assert _parse_position("raw") == ("raw", "")

    def test_with_spaces(self) -> None:
        assert _parse_position("  header:Content-Type  ") == ("header", "Content-Type")


# ===========================================================================
# Tests de l'application des payloads
# ===========================================================================


class TestApplyPayload:
    """Tests de _apply_payload()."""

    BASE_REQUEST = {
        "method": "GET",
        "url": "https://example.com/page?user=admin&debug=1",
        "headers": {
            "Host": "example.com",
            "X-Custom": "original",
            "Cookie": "PHPSESSID=abc123; lang=fr",
        },
        "body": '{"username": "admin", "role": "user"}',
    }

    def test_header_payload(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "header:X-Custom", "INJECTED")
        assert modified["headers"]["X-Custom"] == "INJECTED"
        assert modified["headers"]["Host"] == "example.com"  # Inchangé
        assert modified["url"] == self.BASE_REQUEST["url"]  # Inchangé

    def test_header_new(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "header:X-New", "NEWVAL")
        assert modified["headers"]["X-New"] == "NEWVAL"

    def test_param_payload(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "param:user", "INJECTED")
        assert "user=INJECTED" in modified["url"]
        assert "debug=1" in modified["url"]  # Autre param inchangé

    def test_param_new(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "param:newparam", "NEWVAL")
        assert "newparam=NEWVAL" in modified["url"]

    def test_body_json_key(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "body:username", "INJECTED")
        body = json.loads(modified["body"])  # type: ignore[arg-type]
        assert body["username"] == "INJECTED"
        assert body["role"] == "user"  # Inchangé

    def test_body_nested_key(self) -> None:
        request = {
            "method": "POST",
            "url": "https://example.com/api",
            "headers": {"Content-Type": "application/json"},
            "body": '{"user": {"name": "admin", "email": "a@b.com"}}',
        }
        modified = _apply_payload(request, "body:user.name", "INJECTED")
        body = json.loads(modified["body"])  # type: ignore[arg-type]
        assert body["user"]["name"] == "INJECTED"
        assert body["user"]["email"] == "a@b.com"

    def test_body_raw(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "body:", "RAW_PAYLOAD")
        assert modified["body"] == "RAW_PAYLOAD"

    def test_body_form_urlencoded(self) -> None:
        request = {
            "method": "POST",
            "url": "https://example.com/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "username=admin&password=secret",
        }
        modified = _apply_payload(request, "body:username", "INJECTED")
        assert "username=INJECTED" in modified["body"]  # type: ignore[operator]
        assert "password=secret" in modified["body"]  # type: ignore[operator]

    def test_path_payload(self) -> None:
        request = {
            "method": "GET",
            "url": "https://example.com/api/users/123",
            "headers": {},
            "body": None,
        }
        modified = _apply_payload(request, "path:3", "INJECTED")
        assert "api/users/INJECTED" in modified["url"]

    def test_path_by_name(self) -> None:
        request = {
            "method": "GET",
            "url": "https://example.com/api/users/123",
            "headers": {},
            "body": None,
        }
        modified = _apply_payload(request, "path:users", "INJECTED")
        assert "api/INJECTED/123" in modified["url"]

    def test_cookie_payload(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "cookie:PHPSESSID", "INJECTED")
        cookie = modified["headers"].get("Cookie", "")
        assert "PHPSESSID=INJECTED" in cookie
        assert "lang=fr" in cookie  # Autre cookie inchangé

    def test_cookie_new(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "cookie:newcookie", "NEWVAL")
        cookie = modified["headers"].get("Cookie", "")
        assert "newcookie=NEWVAL" in cookie

    def test_raw_payload(self) -> None:
        modified = _apply_payload(self.BASE_REQUEST, "raw", "RAW_BODY")
        assert modified["body"] == "RAW_BODY"

    def test_payload_preserves_original(self) -> None:
        """Vérifie que la requête originale n'est pas mutée."""
        {
            "method": self.BASE_REQUEST["method"],
            "url": self.BASE_REQUEST["url"],
            "headers": dict(self.BASE_REQUEST["headers"]),
            "body": self.BASE_REQUEST["body"],
        }
        _apply_payload(self.BASE_REQUEST, "header:X-Custom", "INJECTED")
        assert self.BASE_REQUEST["headers"]["X-Custom"] == "original"

    def test_bytes_body(self) -> None:
        request = {
            "method": "POST",
            "url": "https://example.com",
            "headers": {},
            "body": b"original body",
        }
        modified = _apply_payload(request, "raw", "PAYLOAD")
        assert isinstance(modified["body"], bytes)
        assert modified["body"] == b"PAYLOAD"


# ===========================================================================
# Tests des helpers internes
# ===========================================================================


class TestHelpers:
    """Tests des fonctions helper internes."""

    def test_set_nested_key(self) -> None:
        d = {"a": {"b": {"c": "original"}}}
        _set_nested_key(d, "a.b.c", "modified")
        assert d["a"]["b"]["c"] == "modified"

    def test_set_nested_key_creates_missing(self) -> None:
        d: dict = {}
        _set_nested_key(d, "x.y.z", "value")
        assert d["x"]["y"]["z"] == "value"

    def test_replace_form_field(self) -> None:
        result = _replace_form_field("a=1&b=2", "a", "INJECTED")
        assert result in {"a=INJECTED&b=2", "b=2&a=INJECTED"}

    def test_replace_form_field_new(self) -> None:
        result = _replace_form_field("a=1&b=2", "c", "NEW")
        assert "c=NEW" in result

    def test_parse_cookies(self) -> None:
        result = _parse_cookies("PHPSESSID=abc123; lang=fr")
        assert result == {"PHPSESSID": "abc123", "lang": "fr"}

    def test_parse_cookies_empty(self) -> None:
        result = _parse_cookies("")
        assert result == {}

    def test_parse_cookies_no_value(self) -> None:
        result = _parse_cookies("invalid")
        # without '=', it might go to the else branch
        assert isinstance(result, dict)


# ===========================================================================
# Tests du moteur Intruder
# ===========================================================================


class TestIntruderUnit:
    """Tests unitaires de la classe Intruder (sans HTTP réel)."""

    @pytest.fixture
    def intruder(self) -> Intruder:
        return Intruder(timeout=5.0, concurrency=5)


# ===========================================================================
# Tests d'intégration avec httpx mocké
# ===========================================================================


class TestIntruderAttackMocked:
    """Tests de l'attaque Intruder avec httpx mocké."""

    @pytest.fixture
    def intruder(self) -> Intruder:
        return Intruder(timeout=5.0, concurrency=5)

    @pytest.mark.asyncio
    async def test_attack_sniper_single_position(self, intruder: Intruder) -> None:
        """Test sniper avec une seule position."""
        request = {
            "method": "GET",
            "url": "https://example.com/page?user=admin",
            "headers": {},
            "body": None,
        }

        # Mocker le client HTTP
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.content = b"<html>OK</html>"
        mock_response.text = "<html>OK</html>"

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(return_value=mock_response)

            report = await intruder.attack(
                request=request,
                positions=["param:user"],
                payloads={"param:user": ["test1", "test2", "test3"]},
                mode="sniper",
            )

        assert report.mode == "sniper"
        assert report.total_requests == 3
        assert len(report.results) == 3
        # Les résultats sont dans l'ordre de asyncio.as_completed, pas forcement
        # l'ordre d'entrée. Vérifier que tous les payloads sont présents.
        payloads_found = [r.payload_value for r in report.results]
        assert sorted(payloads_found) == sorted(["test1", "test2", "test3"])
        assert all(r.status_code == 200 for r in report.results)
        assert mock_client.request.await_count == 3

    @pytest.mark.asyncio
    async def test_attack_sniper_multiple_positions(self, intruder: Intruder) -> None:
        """Test sniper avec plusieurs positions (une position à la fois)."""
        request = {
            "method": "GET",
            "url": "https://example.com/page?id=1",
            "headers": {"X-Custom": "val"},
            "body": None,
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b"OK"
        mock_response.text = "OK"

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(return_value=mock_response)

            report = await intruder.attack(
                request=request,
                positions=["param:id", "header:X-Custom"],
                payloads={"param:id": ["1", "2"], "header:X-Custom": ["A", "B"]},
                mode="sniper",
            )

        # Sniper: chaque position avec ses payloads
        # param:id → 1,2 (2 requêtes) + header:X-Custom → A,B (2 requêtes) = 4 total
        assert report.total_requests == 4
        assert len(report.results) == 4

        # Vérifier les positions alternées
        positions_used = [r.payload_position for r in report.results]
        assert positions_used.count("param:id") == 2
        assert positions_used.count("header:X-Custom") == 2

    @pytest.mark.asyncio
    async def test_attack_cluster_bomb(self, intruder: Intruder) -> None:
        """Test cluster_bomb avec positions simples."""
        request = {
            "method": "GET",
            "url": "https://example.com/page",
            "headers": {},
            "body": None,
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b"OK"
        mock_response.text = "OK"

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(return_value=mock_response)

            report = await intruder.attack(
                request=request,
                positions=["header:X-A", "header:X-B"],
                payloads={
                    "header:X-A": ["a1", "a2"],
                    "header:X-B": ["b1", "b2"],
                },
                mode="cluster_bomb",
            )

        # cluster_bomb: produit cartésien — chaque requête modifie TOUTES les positions
        # simultanément. 2 positions × 2 payloads = 4 combinaisons.
        # Combinaisons: (X-A=a1, X-B=b1), (X-A=a1, X-B=b2), (X-A=a2, X-B=b1), (X-A=a2, X-B=b2)
        assert report.total_requests == 4
        assert len(report.results) == 4
        # Chaque résultat est une combinaison unique
        assert mock_client.request.await_count == 4

    @pytest.mark.asyncio
    async def test_attack_with_grep_match(self, intruder: Intruder) -> None:
        """Test avec grep_match pour détecter un pattern dans la réponse."""
        request = {
            "method": "GET",
            "url": "https://example.com/search?q=test",
            "headers": {},
            "body": None,
        }

        mock_response_match = MagicMock()
        mock_response_match.status_code = 200
        mock_response_match.headers = {}
        mock_response_match.content = b"Reflected: <script>alert(1)</script>"
        mock_response_match.text = "Reflected: <script>alert(1)</script>"

        mock_response_no_match = MagicMock()
        mock_response_no_match.status_code = 200
        mock_response_no_match.headers = {}
        mock_response_no_match.content = b"No reflection here"
        mock_response_no_match.text = "No reflection here"

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(
                side_effect=[
                    mock_response_match,
                    mock_response_no_match,
                ],
            )

            report = await intruder.attack(
                request=request,
                positions=["param:q"],
                payloads={"param:q": ["<script>alert(1)</script>", "safe"]},
                mode="sniper",
                filters={"grep_match": r"<script>"},
            )

        assert len(report.results) == 2
        assert report.results[0].match is True
        assert report.results[1].match is False

    @pytest.mark.asyncio
    async def test_attack_without_positions_raises(self, intruder: Intruder) -> None:
        """attack() lève ValueError si aucune position."""
        with pytest.raises(ValueError, match="Au moins une position"):
            await intruder.attack(
                request={"method": "GET", "url": "https://example.com"},
                positions=[],
                payloads={"test": ["a"]},
                mode="sniper",
            )

    @pytest.mark.asyncio
    async def test_attack_invalid_mode_raises(self, intruder: Intruder) -> None:
        """attack() lève ValueError si le mode est invalide."""
        with pytest.raises(ValueError, match="Mode invalide"):
            await intruder.attack(
                request={"method": "GET", "url": "https://example.com"},
                positions=["param:id"],
                payloads={"param:id": ["a"]},
                mode="invalid",
            )

    @pytest.mark.asyncio
    async def test_attack_with_predefined_payloads(self, intruder: Intruder) -> None:
        """Utilisation de payloads prédéfinis (xss, sqli, etc.)."""
        request = {
            "method": "GET",
            "url": "https://example.com/page?q=test",
            "headers": {},
            "body": None,
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b"OK"
        mock_response.text = "OK"

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(return_value=mock_response)

            # Utiliser le nom d'un payload prédéfini comme clé
            report = await intruder.attack(
                request=request,
                positions=["param:q"],
                payloads={"xss": []},  # Sera résolu via PREDEFINED_PAYLOADS
                mode="sniper",
            )

        # Tous les payloads XSS doivent être testés
        xss_count = len(PREDEFINED_PAYLOADS["xss"])
        assert report.total_requests == xss_count
        assert len(report.results) == xss_count

    @pytest.mark.asyncio
    async def test_attack_request_error_handling(self, intruder: Intruder) -> None:
        """Gestion des erreurs de connexion."""
        request = {
            "method": "GET",
            "url": "https://example.com/page",
            "headers": {},
            "body": None,
        }

        import httpx as _httpx

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(
                side_effect=_httpx.RequestError("Connection refused"),
            )

            report = await intruder.attack(
                request=request,
                positions=["header:X-Custom"],
                payloads={"header:X-Custom": ["test"]},
                mode="sniper",
            )

        assert len(report.results) == 1
        assert report.results[0].error is not None
        assert report.results[0].status_code == 0

    @pytest.mark.asyncio
    async def test_attack_with_filter_status(self, intruder: Intruder) -> None:
        """Les filtres filter_status sont disponibles sur le report (post-filtrage)."""
        request = {
            "method": "GET",
            "url": "https://example.com/page",
            "headers": {},
            "body": None,
        }

        mock_200 = MagicMock(status_code=200, headers={}, content=b"OK", text="OK")
        mock_500 = MagicMock(status_code=500, headers={}, content=b"Error", text="Error")

        with patch.object(intruder, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(side_effect=[mock_200, mock_500])

            report = await intruder.attack(
                request=request,
                positions=["header:X-A", "header:X-B"],
                payloads={"header:X-A": ["a"], "header:X-B": ["b"]},
                mode="sniper",
                filters={"filter_status": [200]},
            )

        # Les filtres sont marqués mais ne suppriment pas les résultats
        # C'est à l'appelant de filtrer après
        assert len(report.results) == 2
        # Le IntruderFilters.matches() est disponible pour post-filtrage
        filters = IntruderFilters(filter_status=[200])
        filtered = [r for r in report.results if filters.matches(r)]
        assert len(filtered) == 1
        assert filtered[0].status_code == 200


# ===========================================================================
# Tests de la fonction utilitaire quick_attack
# ===========================================================================


class TestQuickAttack:
    """Tests de quick_attack()."""

    @pytest.mark.asyncio
    async def test_quick_attack_basic(self) -> None:
        """quick_attack crée un Intruder et lance l'attaque."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.content = b"OK"
        mock_response.text = "OK"

        with (
            patch("navmax.proxy.intruder.Intruder._get_client") as mock_get_client,
            patch("navmax.proxy.intruder.Intruder.close") as mock_close,
        ):
            mock_client = AsyncMock()
            mock_get_client.return_value = mock_client
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_close.return_value = None

            report = await quick_attack(
                url="https://example.com/search?q=test",
                method="GET",
                payload_category="xss",
                mode="sniper",
            )

        assert report.target_url == "https://example.com/search?q=test"
        assert report.mode == "sniper"
        assert len(report.results) > 0
        mock_close.assert_awaited_once()


# ===========================================================================
# Tests de l'intégration avec les modules existants
# ===========================================================================


class TestIntruderIntegration:
    """Vérifie que Intruder peut être importé depuis le package navmax.proxy."""

    def test_import_from_package(self) -> None:
        """Intruder est accessible depuis navmax.proxy."""
        from navmax.proxy import Intruder, IntruderReport, IntruderResult

        assert Intruder is not None
        assert IntruderResult is not None
        assert IntruderReport is not None

    def test_intruder_is_new_class(self) -> None:
        """Intruder est distinct de Fuzzer (classe différente)."""
        from navmax.proxy import Fuzzer, Intruder

        assert Intruder is not Fuzzer

    def test_interface_methods(self) -> None:
        """Intruder expose les méthodes attendues."""
        intruder = Intruder()
        assert hasattr(intruder, "attack")
        assert hasattr(intruder, "close")
        assert callable(intruder.attack)
        assert callable(intruder.close)

    def test_default_constructor(self) -> None:
        """Constructeur par défaut avec valeurs raisonnables."""
        intruder = Intruder()
        assert intruder.timeout == 15.0
        assert intruder.concurrency == 10
        assert intruder.verify_ssl is False
        assert intruder._client is None

    def test_custom_constructor(self) -> None:
        """Constructeur avec valeurs personnalisées."""
        intruder = Intruder(timeout=30.0, concurrency=50, verify_ssl=True)
        assert intruder.timeout == 30.0
        assert intruder.concurrency == 50
        assert intruder.verify_ssl is True


# ===========================================================================
# Test que le fichier ne casse rien d'existant
# ===========================================================================


class TestNoRegression:
    """Vérifie que les imports existants fonctionnent toujours."""

    def test_existing_imports_still_work(self) -> None:
        """Les modules existants de navmax.proxy sont toujours importables."""
        from navmax.proxy import (
            Fuzzer,
            Interceptor,
            ProxyServer,
            Repeater,
        )

        assert ProxyServer is not None
        assert Interceptor is not None
        assert Repeater is not None
        assert Fuzzer is not None

    def test_mitm_still_importable(self) -> None:
        """mitm.py est toujours importable."""
        from navmax.proxy.mitm import CapturedFlow, NavMITMProxy

        assert NavMITMProxy is not None
        assert CapturedFlow is not None
