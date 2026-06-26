"""Tests unitaires pour les connecteurs SIEM (TheHive, MISP, Hub).

Teste :
- AlertData dataclass
- TheHiveConnector (create_alert, health_check)
- MISPConnector (add_event, health_check)
- IntegrationHub (send_alert, add/remove connectors)
- Graceful degradation (pas d'API key, timeout)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from navmax.integrations import (
    AlertData,
    IntegrationHub,
    MISPConnector,
    TheHiveConnector,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _mock_aiohttp_post(status: int, json_data: dict):
    """Crée un mock pour aiohttp.ClientSession.post retournant une réponse.

    Gère correctement le async context manager (async with resp:).
    """
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=json_data)

    # async context manager pour la réponse
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm


def _mock_aiohttp_get(status: int):
    """Crée un mock pour aiohttp.ClientSession.get."""
    mock_resp = MagicMock()
    mock_resp.status = status

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm


# ===========================================================================
# Tests AlertData
# ===========================================================================


class TestAlertData:
    """Tests de la dataclass AlertData."""

    def test_default_creation(self) -> None:
        alert = AlertData(title="Test", description="Description test")
        assert alert.title == "Test"
        assert alert.description == "Description test"
        assert alert.severity == 2  # medium
        assert alert.source == "NavMAX"
        assert alert.tags == []
        assert alert.indicators == []
        assert alert.raw is None

    def test_full_alert(self) -> None:
        alert = AlertData(
            title="Incident critique",
            description="R01D3 découvert sur serveur DMZ",
            severity=4,
            source="NavMAX-Prod",
            tags=["critical", "rce"],
            indicators=[{"type": "ip", "value": "10.0.0.5"}],
            raw={"cve": "CVE-2024-6387"},
        )
        assert alert.severity == 4
        assert alert.tags == ["critical", "rce"]
        assert len(alert.indicators) == 1
        assert alert.raw["cve"] == "CVE-2024-6387"


# ===========================================================================
# Tests TheHiveConnector
# ===========================================================================


class TestTheHiveConnector:
    """Tests unitaires de TheHiveConnector."""

    def test_creation(self) -> None:
        hive = TheHiveConnector("https://hive.local", api_key="key123", timeout=15)
        assert hive.base_url == "https://hive.local"
        assert hive.api_key == "key123"
        assert hive.timeout == 15

    @pytest.mark.asyncio
    async def test_create_alert_no_config(self) -> None:
        """Sans URL ni clé, retourne None silencieusement."""
        hive = TheHiveConnector("", api_key="")
        alert = AlertData(title="Test", description="Test")
        result = await hive.create_alert(alert)
        assert result is None

    @pytest.mark.asyncio
    async def test_create_alert_success(self) -> None:
        """Alerte créée avec succès → retourne l'ID."""
        mock_post = _mock_aiohttp_post(201, {"_id": "alert-123"})

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.post = MagicMock(return_value=mock_post)

            hive = TheHiveConnector("https://hive.local", api_key="key123")
            alert = AlertData(title="Test alert", description="Desc", severity=3)
            alert_id = await hive.create_alert(alert)
            assert alert_id == "alert-123"

    @pytest.mark.asyncio
    async def test_create_alert_api_error(self) -> None:
        """Erreur API → retourne None."""
        mock_post = _mock_aiohttp_post(401, {})

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.post = MagicMock(return_value=mock_post)

            hive = TheHiveConnector("https://hive.local", api_key="bad_key")
            alert = AlertData(title="Test", description="Test")
            result = await hive.create_alert(alert)
            assert result is None

    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        mock_get = _mock_aiohttp_get(200)

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.get = MagicMock(return_value=mock_get)

            hive = TheHiveConnector("https://hive.local", api_key="key123")
            healthy = await hive.health_check()
            assert healthy is True

    @pytest.mark.asyncio
    async def test_health_check_failure(self) -> None:
        mock_get = _mock_aiohttp_get(403)

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.get = MagicMock(return_value=mock_get)

            hive = TheHiveConnector("https://hive.local", api_key="bad_key")
            healthy = await hive.health_check()
            assert healthy is False

    @pytest.mark.asyncio
    async def test_health_check_no_config(self) -> None:
        hive = TheHiveConnector("", api_key="")
        assert await hive.health_check() is False


# ===========================================================================
# Tests MISPConnector
# ===========================================================================


class TestMISPConnector:
    """Tests unitaires de MISPConnector."""

    def test_creation(self) -> None:
        misp = MISPConnector("https://misp.local", api_key="key456", timeout=20)
        assert misp.base_url == "https://misp.local"
        assert misp.api_key == "key456"
        assert misp.timeout == 20

    @pytest.mark.asyncio
    async def test_add_event_no_config(self) -> None:
        """Sans config, retourne None silencieusement."""
        misp = MISPConnector("", api_key="")
        alert = AlertData(title="Test", description="Test")
        result = await misp.add_event(alert)
        assert result is None

    @pytest.mark.asyncio
    async def test_add_event_success(self) -> None:
        mock_post = _mock_aiohttp_post(200, {"Event": {"id": "42"}})

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.post = MagicMock(return_value=mock_post)

            misp = MISPConnector("https://misp.local", api_key="key456")
            alert = AlertData(title="CVE test", description="Test desc", severity=3)
            event_id = await misp.add_event(alert)
            assert event_id == "42"

    @pytest.mark.asyncio
    async def test_add_event_api_error(self) -> None:
        mock_post = _mock_aiohttp_post(500, {})

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.post = MagicMock(return_value=mock_post)

            misp = MISPConnector("https://misp.local", api_key="bad_key")
            alert = AlertData(title="Test", description="Test")
            result = await misp.add_event(alert)
            assert result is None

    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        mock_get = _mock_aiohttp_get(200)

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__aenter__.return_value = mock_session
            mock_session.get = MagicMock(return_value=mock_get)

            misp = MISPConnector("https://misp.local", api_key="key456")
            healthy = await misp.health_check()
            assert healthy is True


# ===========================================================================
# Tests IntegrationHub
# ===========================================================================


class _MockHive:
    """Connecteur TheHive factice pour les tests du Hub."""
    def __init__(self):
        self.create_alert = AsyncMock(return_value="alert-1")


class _MockMISP:
    """Connecteur MISP factice pour les tests du Hub."""
    def __init__(self):
        self.add_event = AsyncMock(return_value="evt-1")


class _MockFailingConnector:
    """Connecteur qui lève une exception."""
    def __init__(self):
        self.add_event = AsyncMock(side_effect=Exception("Service down"))


class _MockNoMethodConnector:
    """Connecteur sans méthode create_alert ni add_event."""
    pass


class TestIntegrationHub:
    """Tests unitaires de IntegrationHub."""

    def test_empty_hub(self) -> None:
        hub = IntegrationHub()
        assert hub.connectors == []

    def test_add_connector(self) -> None:
        hub = IntegrationHub()
        hive = TheHiveConnector("https://hive.local", api_key="key123")
        hub.add_connector("thehive", hive)
        assert "thehive" in hub.connectors

    def test_remove_connector(self) -> None:
        hub = IntegrationHub()
        hub.add_connector("thehive", "dummy")
        hub.remove_connector("thehive")
        assert hub.connectors == []

    @pytest.mark.asyncio
    async def test_send_alert_all_success(self) -> None:
        """Envoie une alerte à tous les connecteurs avec succès."""
        hub = IntegrationHub()
        hub.add_connector("thehive", _MockHive())
        hub.add_connector("misp", _MockMISP())

        alert = AlertData(title="Test", description="Test")
        results = await hub.send_alert(alert)

        assert results["thehive"] == "alert-1"
        assert results["misp"] == "evt-1"

    @pytest.mark.asyncio
    async def test_send_alert_partial_failure(self) -> None:
        """Un connecteur en échec n'affecte pas les autres."""
        hub = IntegrationHub()
        hub.add_connector("thehive", _MockHive())
        hub.add_connector("misp", _MockFailingConnector())

        alert = AlertData(title="Test", description="Test")
        results = await hub.send_alert(alert)

        assert results["thehive"] == "alert-1"
        assert results["misp"] is None

    @pytest.mark.asyncio
    async def test_send_alert_empty_hub(self) -> None:
        """Hub vide → dictionnaire vide."""
        hub = IntegrationHub()
        alert = AlertData(title="Test", description="Test")
        results = await hub.send_alert(alert)
        assert results == {}

    @pytest.mark.asyncio
    async def test_send_alert_unknown_connector(self) -> None:
        """Connecteur sans méthode create_alert/add_event → None."""
        hub = IntegrationHub()
        hub.add_connector("unknown", _MockNoMethodConnector())
        alert = AlertData(title="Test", description="Test")
        results = await hub.send_alert(alert)
        assert results["unknown"] is None
