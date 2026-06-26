"""Connecteur MISP — plateforme de partage d'indicateurs.

Usage:
    misp = MISPConnector("https://misp.example.com", api_key="...")
    await misp.add_event(AlertData(title="CVE-2024-6387", severity=4))
"""

import structlog

from .thehive import AlertData

logger = structlog.get_logger(__name__)


class MISPConnector:
    """Connecteur pour MISP (plateforme de partage d'indicateurs).

    Ajoute des événements avec attributs dans l'instance MISP distante.
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def add_event(self, alert: AlertData) -> str | None:
        """Ajoute un événement dans MISP.

        Args:
            alert: Données de l'alerte à créer comme événement MISP.

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
                "analysis": "1",  # Initial
                "published": False,
                "Attribute": [
                    {
                        "type": "comment",
                        "category": "Other",
                        "value": alert.description[:500],
                    },
                ],
            },
        }

        for ind in alert.indicators:
            payload["Event"]["Attribute"].append(
                {
                    "type": ind.get("misp_type", ind.get("type", "ip-dst")),
                    "category": ind.get("category", "Network activity"),
                    "value": ind.get("value", ""),
                },
            )

        headers = {
            "Authorization": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            async with (
                aiohttp.ClientSession() as s,
                s.post(
                    f"{self.base_url}/events",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp,
            ):
                if resp.status in (200, 201):
                    data = await resp.json()
                    event_id = data.get("Event", {}).get("id", "")
                    logger.info("misp_event_created", id=event_id)
                    return str(event_id)
                logger.warning("misp_error", status=resp.status)
                return None
        except (TimeoutError, aiohttp.ClientError) as e:
            logger.exception("misp_connection_failed", error=str(e))
            return None

    async def health_check(self) -> bool:
        """Vérifie si l'API MISP est accessible."""
        if not self.base_url or not self.api_key:
            return False
        import aiohttp

        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": self.api_key}
                async with s.get(
                    f"{self.base_url}/events/index", headers=headers, timeout=10,
                ) as resp:
                    return resp.status == 200
        except (TimeoutError, aiohttp.ClientError):
            return False
