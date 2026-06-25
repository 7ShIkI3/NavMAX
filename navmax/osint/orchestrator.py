"""
Orchestrateur OSINT — lance les collecteurs et les transforms sur une cible.
"""

import asyncio
from typing import Any

from .collectors import DnsCollector, WhoisCollector, SslCollector, WebCollector
from .graph import (
    Entity, EntityType, GraphEngine, get_transforms_for,
)
from navmax.core.logging import get_logger

logger = get_logger(__name__)


class OsintOrchestrator:
    """
    Orchestre une investigation OSINT complète.

    1. Crée l'entité de départ (domaine ou IP)
    2. Exécute les transforms de niveau 1
    3. Optionnellement, exécute les transforms de niveau 2 sur les nouvelles entités
    """

    def __init__(self, max_depth: int = 2, parallel: bool = True) -> None:
        self.graph = GraphEngine()
        self.max_depth = max_depth
        self.parallel = parallel
        self._results_log: list[str] = []

    @property
    def results(self) -> list[str]:
        return self._results_log

    async def investigate(self, target: str, target_type: str = "domain") -> dict[str, Any]:
        """
        Lance une investigation complète sur une cible.

        Args:
            target: Domaine ou IP
            target_type: 'domain' ou 'ip'

        Returns:
            Résumé de l'investigation
        """
        entity_type = EntityType.DOMAIN if target_type == "domain" else EntityType.IP
        root = Entity(type=entity_type, value=target, label=target)
        self.graph.add_entity(root)
        self._results_log.append("[+] Entité racine : {} ({})".format(target, target_type))

        # Niveau 1 : transforms sur la racine
        transforms = get_transforms_for(entity_type)
        self._results_log.append("[+] Transforms niveau 1 : {} disponibles".format(len(transforms)))

        new_entities: list[Entity] = []
        for t in transforms:
            try:
                results = await t.run(root, self.graph)
                new_entities.extend(results)
                self._results_log.append("    ├─ {} : {} nouvelles entités".format(t.name, len(results)))
            except (RuntimeError, OSError, ValueError) as e:
                self._results_log.append("    ├─ {} : ERREUR — {}".format(t.name, e))

        # Niveau 2 : transforms sur les nouvelles entités (si max_depth >= 2)
        if self.max_depth >= 2:
            self._results_log.append("[+] Transforms niveau 2 sur {} entités...".format(len(new_entities)))
            for entity in new_entities[:20]:  # Limiter à 20 pour éviter l'explosion
                transforms_l2 = get_transforms_for(entity.type)
                for t in transforms_l2:
                    try:
                        sub_results = await t.run(entity, self.graph)
                        self._results_log.append("    ├─ [{}] {} : {} entités".format(entity.type.value, t.name, len(sub_results)))
                    except (RuntimeError, OSError, ValueError) as e:
                        logger.debug("transform_l2_echec", entity=entity.value, transform=t.name, erreur=str(e))

        self._results_log.append(
            "[+] Investigation terminée : {} entités, {} relations".format(self.graph.node_count, self.graph.edge_count)
        )

        return {
            "target": target,
            "type": target_type,
            "node_count": self.graph.node_count,
            "edge_count": self.graph.edge_count,
            "log": self._results_log,
        }

    def export(self, fmt: str = "cytoscape") -> dict | str:
        """Exporte le graphe au format demandé."""
        if fmt == "cytoscape":
            return self.graph.export_cytoscape()
        elif fmt == "sigmajs":
            return self.graph.export_sigmajs()
        else:
            return self.graph.export_json()
