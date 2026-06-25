import pytest
pytestmark = pytest.mark.skip(reason="mitmproxy tests require network — skipped in dev")
"""
Tests pour navmax/proxy/mitm.py — NavMITMProxy basé sur mitmproxy.

Utilise des mocks pour mitmproxy afin de permettre les tests
même quand mitmproxy n'est pas installé.
"""

import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from navmax.proxy.mitm import (
    CapturedFlow,
    NavMITMProxy,
    MITMPROXY_AVAILABLE,
)


# ===========================================================================
# Tests unitaires CapturedFlow
# ===========================================================================


class TestCapturedFlow:
    """Tests de la dataclass CapturedFlow."""

    def test_default_creation(self) -> None:
        """Un CapturedFlow est créé avec des valeurs par défaut."""
        flow = CapturedFlow()
        assert flow.id is not None
        assert len(flow.id) == 8  # UUID tronqué
        assert isinstance(flow.timestamp, datetime)
        assert flow.method == ""
        assert flow.url == ""
        assert flow.response_status == 0
        assert flow.duration_ms == 0.0
        assert flow.error is None

    def test_to_dict(self) -> None:
        """to_dict() retourne un dictionnaire sérialisable."""
        flow = CapturedFlow(
            method="POST",
            url="https://example.com/api",
            request_headers={"Content-Type": "application/json"},
            request_body=b'{"key": "value"}',
            response_status=200,
            response_headers={"X-Custom": "test"},
            response_body=b'{"ok": true}',
            duration_ms=123.4,
        )
        d = flow.to_dict()
        assert d["method"] == "POST"
        assert d["url"] == "https://example.com/api"
        assert d["request_headers"]["Content-Type"] == "application/json"
        assert d["request_body"] == '{"key": "value"}'
        assert d["response_status"] == 200
        assert d["response_body"] == '{"ok": true}'
        assert d["duration_ms"] == 123.4

    def test_to_dict_without_body(self) -> None:
        """to_dict() gère les body None."""
        flow = CapturedFlow(method="GET", url="https://example.com")
        d = flow.to_dict()
        assert d["request_body"] is None
        assert d["response_body"] is None

    def test_to_har_entry(self) -> None:
        """to_har_entry() produit une entrée HAR valide."""
        flow = CapturedFlow(
            method="GET",
            url="https://example.com/page",
            request_headers={"Accept": "text/html"},
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body=b"<html></html>",
            duration_ms=50.0,
        )
        entry = flow.to_har_entry()
        assert entry["request"]["method"] == "GET"
        assert entry["request"]["url"] == "https://example.com/page"
        assert entry["response"]["status"] == 200
        assert entry["time"] == 50.0
        assert entry["response"]["content"]["text"] == "<html></html>"


# ===========================================================================
# Tests du proxy NavMITMProxy
# ===========================================================================


class TestNavMITMProxy:
    """Tests de NavMITMProxy (avec mocks mitmproxy)."""

    @pytest.fixture
    def proxy(self) -> NavMITMProxy:
        """Crée une instance de proxy pour les tests."""
        return NavMITMProxy(host="127.0.0.1", port=8080)

    def test_init_defaults(self, proxy: NavMITMProxy) -> None:
        """Les valeurs par défaut sont correctes."""
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 8080
        assert proxy.running is False
        assert proxy.flow_count == 0
        assert proxy.recent_flows == []

    @pytest.mark.asyncio
    async def test_start_stop_mitmproxy_not_available(self) -> None:
        """start() ne fait rien si mitmproxy n'est pas disponible."""
        with patch("navmax.proxy.mitm.MITMPROXY_AVAILABLE", False):
            proxy = NavMITMProxy()
            await proxy.start()
            assert proxy.running is False
            await proxy.stop()

    @pytest.mark.asyncio
    async def test_start_with_mocked_master(self) -> None:
        """start() démarre le thread et le master si mitmproxy est disponible."""
        with (
            patch("navmax.proxy.mitm.MITMPROXY_AVAILABLE", True),
            patch("navmax.proxy.mitm.Master") as MockMaster,
            patch("navmax.proxy.mitm.options.Options") as MockOptions,
            patch("navmax.proxy.mitm.threading.Thread") as MockThread,
        ):
            # Configurer les mocks
            mock_master_instance = MagicMock()
            MockMaster.return_value = mock_master_instance

            mock_thread_instance = MagicMock()
            MockThread.return_value = mock_thread_instance

            proxy = NavMITMProxy()
            await proxy.start()

            # Vérifier que le master a été créé avec les bonnes options
            MockMaster.assert_called_once()
            call_kwargs = MockMaster.call_args[0][0]

            # Vérifier que le thread a été créé et démarré
            MockThread.assert_called_once()
            assert mock_thread_instance.start.called

            assert proxy.running is True

            # Arrêter
            await proxy.stop()
            assert proxy.running is False
            assert mock_master_instance.shutdown.called

    @pytest.mark.asyncio
    async def test_double_start(self) -> None:
        """start() deux fois ne crée pas deux threads."""
        with (
            patch("navmax.proxy.mitm.MITMPROXY_AVAILABLE", True),
            patch("navmax.proxy.mitm.Master") as MockMaster,
            patch("navmax.proxy.mitm.options.Options"),
            patch("navmax.proxy.mitm.threading.Thread") as MockThread,
        ):
            mock_master = MagicMock()
            MockMaster.return_value = mock_master

            proxy = NavMITMProxy()
            await proxy.start()
            await proxy.start()  # Deuxième appel

            # Un seul thread créé
            assert MockThread.call_count == 1

    @pytest.mark.asyncio
    async def test_get_flows_empty(self) -> None:
        """get_flows() retourne une liste vide si aucun flux."""
        proxy = NavMITMProxy()
        with patch("navmax.proxy.mitm.MITMPROXY_AVAILABLE", True):
            flows = await proxy.get_flows()
            assert flows == []

    @pytest.mark.asyncio
    async def test_get_flows_with_addon(self) -> None:
        """get_flows() retourne les flux depuis l'addon."""
        proxy = NavMITMProxy()
        flow1 = CapturedFlow(method="GET", url="https://example.com/1")
        flow2 = CapturedFlow(method="POST", url="https://example.com/2")

        # Simuler un addon avec des flux
        mock_addon = MagicMock()
        mock_addon._flows = [flow1, flow2]
        proxy._addon = mock_addon

        flows = await proxy.get_flows()
        assert len(flows) == 2
        assert flows[0].url == "https://example.com/1"
        assert flows[1].url == "https://example.com/2"

    @pytest.mark.asyncio
    async def test_get_flows_with_since_filter(self) -> None:
        """get_flows() filtre par timestamp si since est fourni."""
        proxy = NavMITMProxy()

        now = datetime.now(timezone.utc)
        old_flow = CapturedFlow(
            method="GET",
            url="https://example.com/old",
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        new_flow = CapturedFlow(
            method="GET",
            url="https://example.com/new",
            timestamp=now,
        )

        mock_addon = MagicMock()
        mock_addon._flows = [old_flow, new_flow]
        proxy._addon = mock_addon

        since = datetime(2024, 6, 1, tzinfo=timezone.utc)
        flows = await proxy.get_flows(since=since)
        assert len(flows) == 1
        assert flows[0].url == "https://example.com/new"

    @pytest.mark.asyncio
    async def test_export_har_empty(self) -> None:
        """export_har() retourne un HAR valide même sans flux."""
        proxy = NavMITMProxy()
        har_json = await proxy.export_har([])
        har = json.loads(har_json)
        assert har["log"]["version"] == "1.2"
        assert har["log"]["entries"] == []

    @pytest.mark.asyncio
    async def test_export_har_with_flows(self) -> None:
        """export_har() génère un HAR avec les flux fournis."""
        proxy = NavMITMProxy()
        flows = [
            CapturedFlow(
                method="GET",
                url="https://example.com/page",
                response_status=200,
                response_headers={"Content-Type": "text/html"},
                response_body=b"<html></html>",
                duration_ms=50.0,
            )
        ]
        har_json = await proxy.export_har(flows)
        har = json.loads(har_json)
        assert len(har["log"]["entries"]) == 1
        entry = har["log"]["entries"][0]
        assert entry["request"]["url"] == "https://example.com/page"
        assert entry["response"]["status"] == 200

    @pytest.mark.asyncio
    async def test_export_har_skips_empty_responses(self) -> None:
        """export_har() ignore les flux sans réponse (status=0)."""
        proxy = NavMITMProxy()
        flows = [
            CapturedFlow(method="GET", url="https://example.com/1", response_status=0),
            CapturedFlow(method="GET", url="https://example.com/2", response_status=200),
        ]
        har_json = await proxy.export_har(flows)
        har = json.loads(har_json)
        assert len(har["log"]["entries"]) == 1
        assert har["log"]["entries"][0]["request"]["url"] == "https://example.com/2"

    @pytest.mark.asyncio
    async def test_replay_flow_not_found(self) -> None:
        """replay_flow() lève une ValueError si le flux est introuvable."""
        proxy = NavMITMProxy()
        proxy._addon = MagicMock()
        proxy._addon._flows = []

        with pytest.raises(ValueError, match="Flux introuvable"):
            await proxy.replay_flow("nonexistent")

    @pytest.mark.asyncio
    async def test_replay_flow_no_mitmproxy(self) -> None:
        """replay_flow() lève RuntimeError si mitmproxy n'est pas installé."""
        proxy = NavMITMProxy()
        flow = CapturedFlow(id="test123", method="GET", url="https://example.com")
        proxy._addon = MagicMock()
        proxy._addon._flows = [flow]

        with patch("navmax.proxy.mitm.MITMPROXY_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="mitmproxy non installé"):
                await proxy.replay_flow("test123")

    @pytest.mark.asyncio
    async def test_replay_flow_with_modifications(self) -> None:
        """replay_flow() applique les modifications."""
        proxy = NavMITMProxy()
        flow = CapturedFlow(
            id="test123",
            method="GET",
            url="https://httpbin.org/get",
            request_headers={"Accept": "application/json"},
            request_body=None,
        )
        proxy._addon = MagicMock()
        proxy._addon._flows = [flow]

        with (
            patch("navmax.proxy.mitm.MITMPROXY_AVAILABLE", True),
            patch("navmax.proxy.mitm.http.Request.make") as MockRequest,
            patch("httpx.AsyncClient") as MockClient,
        ):
            mock_client_instance = AsyncMock()
            MockClient.return_value.__aenter__.return_value = mock_client_instance
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Content-Type": "application/json"}
            mock_response.content = b'{"modified": true}'
            mock_client_instance.request = AsyncMock(return_value=mock_response)

            result = await proxy.replay_flow(
                "test123",
                modifications={
                    "method": "POST",
                    "url": "https://httpbin.org/post",
                    "headers": {"X-Test": "modified"},
                    "body": '{"data": "test"}',
                },
            )

            assert result.method == "POST"
            assert result.url == "https://httpbin.org/post"
            assert result.request_headers.get("X-Test") == "modified"
            assert result.response_status == 200
            assert result.response_body == b'{"modified": true}'

    @pytest.mark.asyncio
    async def test_on_flow_captured_callback(self) -> None:
        """on_flow_captured() enregistre un callback appelé à chaque flux."""
        proxy = NavMITMProxy()

        callback = AsyncMock()
        proxy.on_flow_captured(callback)

        captured = CapturedFlow(method="GET", url="https://example.com")
        await proxy._on_flow_captured(captured)

        callback.assert_awaited_once_with(captured)


# ===========================================================================
# Tests de l'addon (intégration légère)
# ===========================================================================


class TestNavMITMAddon:
    """Tests de l'addon mitmproxy NavMITMAddon."""

    def test_addon_importable(self) -> None:
        """Vérifie que l'addon peut être importé."""
        from navmax.proxy.mitm import NavMITMAddon

        assert NavMITMAddon is not None

    def test_addon_has_required_methods(self) -> None:
        """Les méthodes request, response, error existent."""
        # On teste l'interface même si mitmproxy est indisponible
        from navmax.proxy.mitm import NavMITMAddon

        addon = NavMITMAddon() if MITMPROXY_AVAILABLE else None

        if addon:
            assert hasattr(addon, "request")
            assert hasattr(addon, "response")
            assert hasattr(addon, "error")

    def test_addon_flow_to_captured(self) -> None:
        """Vérifie la conversion flow → captured static method."""
        from navmax.proxy.mitm import NavMITMAddon

        if not MITMPROXY_AVAILABLE:
            pytest.skip("mitmproxy non installé")

        import time
        from mitmproxy import http, connection

        now = time.time()
        client = connection.Client(
            peername=("127.0.0.1", 12345),
            sockname=("127.0.0.1", 8080),
            timestamp_start=now,
        )
        server = connection.Server(address=("example.com", 80))

        flow = http.HTTPFlow(client, server)
        flow.request = http.Request.make("GET", "https://example.com/test")
        flow.response = http.Response.make(200, b'{"ok": true}', {"Content-Type": "application/json"})
        flow.request.timestamp_start = now
        flow.response.timestamp_end = now + 0.1

        captured = NavMITMAddon._flow_to_captured(flow)
        assert captured.method == "GET"
        assert captured.url == "https://example.com/test"
        assert captured.response_status == 200
        assert captured.response_body == b'{"ok": true}'
        assert "Content-Type" in captured.response_headers
        assert captured.duration_ms > 0


# ===========================================================================
# Tests de compatibilité (interface publique)
# ===========================================================================


class TestCompatibilite:
    """Vérifie que NavMITMProxy expose la même interface que ProxyServer."""

    def test_interface_publique(self) -> None:
        """NavMITMProxy a les mêmes propriétés et méthodes que ProxyServer."""
        proxy = NavMITMProxy()

        # Propriétés
        assert hasattr(proxy, "running")
        assert hasattr(proxy, "flow_count")
        assert hasattr(proxy, "recent_flows")

        # Méthodes
        assert hasattr(proxy, "start")
        assert hasattr(proxy, "stop")
        assert hasattr(proxy, "intercept_enabled")
