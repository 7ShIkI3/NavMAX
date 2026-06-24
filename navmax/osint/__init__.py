"""
Module OSINT — reconnaissance et graphe (Maltego-like).

Fonctionnalités :
- Collecteurs : DNS, WHOIS, SSL, Web scraping
- Moteur de graphe : NetworkX, entités, relations
- Transforms : règles d'expansion automatique
- Export : JSON, Cytoscape.js, Sigma.js
- Orchestrateur : investigation automatisée
"""

from .collectors import (
    DnsCollector, DnsRecord,
    WhoisCollector, WhoisInfo,
    SslCollector, SslCertInfo,
    WebCollector, WebTechInfo,
)
from .graph import (
    Entity, Relation, EntityType, RelationType,
    GraphEngine,
    Transform, get_transforms_for, ALL_TRANSFORMS,
)
from .orchestrator import OsintOrchestrator

__all__ = [
    "DnsCollector", "DnsRecord",
    "WhoisCollector", "WhoisInfo",
    "SslCollector", "SslCertInfo",
    "WebCollector", "WebTechInfo",
    "Entity", "Relation", "EntityType", "RelationType",
    "GraphEngine",
    "Transform", "get_transforms_for", "ALL_TRANSFORMS",
    "OsintOrchestrator",
]
