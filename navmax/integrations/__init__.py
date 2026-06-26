"""Connecteurs SIEM/SOAR — TheHive, MISP, Hub central.

Envoie les alertes NavMAX (découvertes, exploits réussis) vers
des systèmes de gestion d'incidents.

Usage:
    from navmax.integrations import (
        AlertData, TheHiveConnector, MISPConnector, IntegrationHub
    )
"""

from .hub import IntegrationHub
from .misp import MISPConnector
from .thehive import AlertData, TheHiveConnector

__all__ = [
    "AlertData",
    "IntegrationHub",
    "MISPConnector",
    "TheHiveConnector",
]
