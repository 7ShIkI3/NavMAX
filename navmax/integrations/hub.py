"""Hub central — agrège tous les connecteurs SIEM/SOAR.

Usage:
    hub = IntegrationHub()
    hub.add_connector("thehive", TheHiveConnector(...))
    hub.add_connector("misp", MISPConnector(...))
    await hub.send_alert(alert_data)  # envoie à tous les connecteurs
"""

import structlog

from .thehive import AlertData

logger = structlog.get_logger(__name__)


class IntegrationHub:
    """Hub central pour tous les connecteurs SIEM/SOAR.

    Agrège les connecteurs (TheHive, MISP, etc.) et envoie les alertes
    à tous les connecteurs enregistrés en parallèle.
    """

    def __init__(self) -> None:
        self._connectors: dict[str, object] = {}

    def add_connector(self, name: str, connector) -> None:
        """Enregistre un connecteur dans le hub.

        Args:
            name: Identifiant unique du connecteur.
            connector: Instance du connecteur (TheHiveConnector, MISPConnector, etc.).

        """
        self._connectors[name] = connector

    def remove_connector(self, name: str) -> None:
        """Retire un connecteur du hub."""
        self._connectors.pop(name, None)

    async def send_alert(self, alert: AlertData) -> dict[str, str | None]:
        """Envoie une alerte à tous les connecteurs enregistrés.

        Args:
            alert: Données de l'alerte à distribuer.

        Returns:
            Dictionnaire {nom_connecteur: result_id} — None si échec.

        """
        results = {}
        for name, conn in self._connectors.items():
            try:
                if hasattr(conn, "create_alert"):
                    rid = await conn.create_alert(alert)
                elif hasattr(conn, "add_event"):
                    rid = await conn.add_event(alert)
                else:
                    rid = None
                results[name] = rid
            except Exception as e:
                logger.exception("connector_failed", name=name, error=str(e))
                results[name] = None
        return results

    @property
    def connectors(self) -> list[str]:
        """Liste des noms de connecteurs enregistrés."""
        return list(self._connectors.keys())
