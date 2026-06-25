"""
Connecteurs SIEM/SOAR — TheHive, MISP.

Envoie les alertes NavMAX (découvertes, exploits réussis) vers
des systèmes de gestion d'incidents.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class AlertData:
    """Données d'une alerte à envoyer."""
    title: str
    description: str
    severity: int = 2          # 1=low, 2=medium, 3=high, 4=critical
    source: str = "NavMAX"
    tags: list[str] = field(default_factory=list)
    indicators: list[dict] = field(default_factory=list)
    raw: Optional[dict] = None


class TheHiveConnector:
    """Connecteur pour TheHive (gestion d'incidents).

    Usage:
        hive = TheHiveConnector("https://thehive.example.com", api_key="...")
        await hive.create_alert(AlertData(title="Redis unauth", severity=3))
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def create_alert(self, alert: AlertData) -> Optional[str]:
        """Crée une alerte dans TheHive.

        Returns:
            ID de l'alerte créée, ou None si échec.
        """
        if not self.base_url or not self.api_key:
            logger.warning("thehive_non_configure", message="TheHive non configuré — alerte ignorée")
            return None

        import aiohttp

        payload = {
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "source": alert.source,
            "sourceRef": f"navmax-{alert.title.lower().replace(' ', '-')[:50]}",
            "tags": alert.tags,
            "type": "external",
        }

        if alert.indicators:
            payload["observables"] = [
                {"dataType": i.get("type", "ip"), "data": i.get("value", "")}
                for i in alert.indicators
            ]

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.base_url}/api/v1/alert",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        alert_id = data.get("_id", "")
                        logger.info("thehive_alert_created", id=alert_id)
                        return alert_id
                    else:
                        logger.warning("thehive_error", status=resp.status)
                        return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error("thehive_connection_failed", error=str(e))
            return None

    async def health_check(self) -> bool:
        if not self.base_url or not self.api_key:
            return False
        import aiohttp
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with s.get(f"{self.base_url}/api/v1/status",
                                 headers=headers, timeout=10) as resp:
                    return resp.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False


class MISPConnector:
    """Connecteur pour MISP (plateforme de partage d'indicateurs).

    Usage:
        misp = MISPConnector("https://misp.example.com", api_key="...")
        await misp.add_event(AlertData(title="CVE-2024-6387", severity=4))
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def add_event(self, alert: AlertData) -> Optional[str]:
        """Ajoute un événement dans MISP.

        Returns:
            ID de l'événement, ou None si échec.
        """
        if not self.base_url or not self.api_key:
            logger.warning("misp_non_configure", message="MISP non configuré — événement ignoré")
            return None

        import aiohttp

        payload = {
            "Event": {
                "info": alert.title,
                "distribution": "0",  # Your organisation only
                "threat_level_id": str(min(alert.severity, 4)),
                "analysis": "1",       # Initial
                "published": False,
                "Attribute": [
                    {
                        "type": "comment",
                        "category": "Other",
                        "value": alert.description[:500],
                    }
                ],
            }
        }

        for ind in alert.indicators:
            payload["Event"]["Attribute"].append({
                "type": ind.get("misp_type", ind.get("type", "ip-dst")),
                "category": ind.get("category", "Network activity"),
                "value": ind.get("value", ""),
            })

        headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self.base_url}/events",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        event_id = data.get("Event", {}).get("id", "")
                        logger.info("misp_event_created", id=event_id)
                        return str(event_id)
                    else:
                        logger.warning("misp_error", status=resp.status)
                        return None
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error("misp_connection_failed", error=str(e))
            return None

    async def health_check(self) -> bool:
        if not self.base_url or not self.api_key:
            return False
        import aiohttp
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": self.api_key}
                async with s.get(f"{self.base_url}/events/index",
                                 headers=headers, timeout=10) as resp:
                    return resp.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False


class IntegrationHub:
    """Hub central pour tous les connecteurs SIEM/SOAR.

    Usage:
        hub = IntegrationHub()
        hub.add_connector("thehive", TheHiveConnector(...))
        hub.add_connector("misp", MISPConnector(...))
        await hub.send_alert(alert_data)  # envoie à tous les connecteurs
    """

    def __init__(self):
        self._connectors: dict[str, object] = {}

    def add_connector(self, name: str, connector):
        self._connectors[name] = connector

    def remove_connector(self, name: str):
        self._connectors.pop(name, None)

    async def send_alert(self, alert: AlertData) -> dict[str, Optional[str]]:
        """Envoie une alerte à tous les connecteurs.

        Returns:
            {connector_name: result_id}
        """
        results = {}
        for name, conn in self._connectors.items():
            try:
                if hasattr(conn, 'create_alert'):
                    rid = await conn.create_alert(alert)
                elif hasattr(conn, 'add_event'):
                    rid = await conn.add_event(alert)
                else:
                    rid = None
                results[name] = rid
            except Exception as e:
                logger.error("connector_failed", name=name, error=str(e))
                results[name] = None
        return results

    @property
    def connectors(self) -> list[str]:
        return list(self._connectors.keys())
