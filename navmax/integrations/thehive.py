"""Connecteur TheHive — gestion d'incidents SIEM.

Usage:
    hive = TheHiveConnector("https://thehive.example.com", api_key="...")
    await hive.create_alert(AlertData(title="Redis unauth", severity=3))
"""

from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class AlertData:
    """Données d'une alerte à envoyer vers SIEM/SOAR."""

    title: str
    description: str
    severity: int = 2  # 1=low, 2=medium, 3=high, 4=critical
    source: str = "NavMAX"
    tags: list[str] = field(default_factory=list)
    indicators: list[dict] = field(default_factory=list)
    raw: dict | None = None


class TheHiveConnector:
    """Connecteur pour TheHive (gestion d'incidents).

    Envoie des alertes vers l'API REST de TheHive v1.
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def create_alert(self, alert: AlertData) -> str | None:
        """Crée une alerte dans TheHive.

        Args:
            alert: Données de l'alerte à créer.

        Returns:
            ID de l'alerte créée, ou None si échec.

        """
        if not self.base_url or not self.api_key:
            logger.warning(
                "thehive_non_configure", message="TheHive non configuré — alerte ignorée",
            )
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
            async with (
                aiohttp.ClientSession() as s,
                s.post(
                    f"{self.base_url}/api/v1/alert",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp,
            ):
                if resp.status in (200, 201):
                    data = await resp.json()
                    alert_id = data.get("_id", "")
                    logger.info("thehive_alert_created", id=alert_id)
                    return alert_id
                logger.warning("thehive_error", status=resp.status)
                return None
        except (TimeoutError, aiohttp.ClientError) as e:
            logger.exception("thehive_connection_failed", error=str(e))
            return None

    async def health_check(self) -> bool:
        """Vérifie si l'API TheHive est accessible."""
        if not self.base_url or not self.api_key:
            return False
        import aiohttp

        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with s.get(
                    f"{self.base_url}/api/v1/status", headers=headers, timeout=10,
                ) as resp:
                    return resp.status == 200
        except (TimeoutError, aiohttp.ClientError):
            return False
