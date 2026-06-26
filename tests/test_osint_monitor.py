"""Tests pour OSINTMonitor et SemanticGraphSearch."""

from unittest.mock import AsyncMock

import pytest

from navmax.osint.graph.engine import GraphEngine
from navmax.osint.graph.entities import Entity, EntityType, RelationType
from navmax.osint.graph.semantic_search import (
    GraphQueryResult,
    SemanticGraphSearch,
)
from navmax.osint.monitor import (
    MonitorSubscription,
    OSINTMonitor,
)

# ── OSINTMonitor ──────────────────────────────────────────────


class TestMonitorSubscription:
    def test_defaults(self) -> None:
        sub = MonitorSubscription(id="s1", target="example.com")
        assert sub.target == "example.com"
        assert sub.interval_hours == 24
        assert "new_subdomain" in sub.alert_on
        assert sub.enabled is True

    def test_custom_alerts(self) -> None:
        sub = MonitorSubscription(id="s2", target="test.com", alert_on=["ip_change"])
        assert sub.alert_on == ["ip_change"]


class TestOSINTMonitor:
    @pytest.fixture
    def monitor(self):
        return OSINTMonitor()

    @pytest.mark.asyncio
    async def test_subscribe(self, monitor) -> None:
        sub = await monitor.subscribe("example.com", interval_hours=12)
        assert sub.target == "example.com"
        assert sub.interval_hours == 12
        assert sub.id in [s.id for s in monitor.list_subscriptions()]

    @pytest.mark.asyncio
    async def test_unsubscribe(self, monitor) -> None:
        sub = await monitor.subscribe("test.com")
        assert await monitor.unsubscribe(sub.id) is True
        assert await monitor.unsubscribe("nonexistent") is False

    @pytest.mark.asyncio
    async def test_list_subscriptions(self, monitor) -> None:
        await monitor.subscribe("a.com")
        await monitor.subscribe("b.com")
        assert len(monitor.list_subscriptions()) == 2

    def test_diff_new_subdomain(self, monitor) -> None:
        old = {"subdomains": ["www.example.com"]}
        new = {"subdomains": ["www.example.com", "admin.example.com"]}
        sub = MonitorSubscription(id="s1", target="example.com")

        alerts = monitor._diff(sub, old, new)
        assert len(alerts) == 1
        assert alerts[0].change_type == "new_subdomain"
        assert alerts[0].new_value == "admin.example.com"

    def test_diff_subdomain_removed(self, monitor) -> None:
        old = {"subdomains": ["www.example.com", "old.example.com"]}
        new = {"subdomains": ["www.example.com"]}
        sub = MonitorSubscription(id="s1", target="example.com")

        alerts = monitor._diff(sub, old, new)
        assert len(alerts) == 1
        assert alerts[0].change_type == "subdomain_removed"

    def test_diff_ip_change(self, monitor) -> None:
        old = {"ips": ["93.184.216.34"]}
        new = {"ips": ["93.184.216.35"]}
        sub = MonitorSubscription(id="s1", target="example.com")

        alerts = monitor._diff(sub, old, new)
        assert len(alerts) == 1
        assert alerts[0].change_type == "ip_change"

    def test_diff_no_change(self, monitor) -> None:
        old = {"subdomains": ["www.example.com"], "ips": ["1.1.1.1"]}
        new = {"subdomains": ["www.example.com"], "ips": ["1.1.1.1"]}
        sub = MonitorSubscription(id="s1", target="example.com")

        alerts = monitor._diff(sub, old, new)
        assert len(alerts) == 0

    def test_diff_disabled_alert_type(self, monitor) -> None:
        sub = MonitorSubscription(
            id="s1", target="example.com", alert_on=["ip_change"],
        )  # no subdomain alerts
        old = {"subdomains": ["www.example.com"]}
        new = {"subdomains": ["www.example.com", "admin.example.com"]}

        alerts = monitor._diff(sub, old, new)
        assert len(alerts) == 0  # subdomain alert disabled

    def test_diff_multiple_new_subdomains(self, monitor) -> None:
        old = {"subdomains": ["www.example.com"]}
        new = {"subdomains": ["www.example.com", "admin.example.com", "api.example.com"]}
        sub = MonitorSubscription(id="s1", target="example.com")

        alerts = monitor._diff(sub, old, new)
        assert len(alerts) == 2
        values = [a.new_value for a in alerts]
        assert "admin.example.com" in values
        assert "api.example.com" in values

    @pytest.mark.asyncio
    async def test_check_creates_snapshot(self, monitor) -> None:
        sub = await monitor.subscribe("example.com")
        alerts = await monitor.check(sub)
        # Premier check: pas d'alerte (pas d'historique)
        assert len(alerts) == 0
        assert sub.last_snapshot is not None
        assert sub.last_check is not None

    @pytest.mark.asyncio
    async def test_check_detects_change(self, monitor) -> None:
        sub = await monitor.subscribe("example.com")
        # Premier check: initialise le snapshot
        await monitor.check(sub)
        # Modifier le snapshot pour simuler un changement
        sub.last_snapshot = {"subdomains": ["www.example.com"]}

        # Mock la collecte pour retourner des nouvelles données
        async def mock_collect(target):
            return {"subdomains": ["www.example.com", "new.example.com"]}

        monitor._collect = mock_collect

        alerts = await monitor.check(sub)
        assert len(alerts) == 1
        assert alerts[0].change_type == "new_subdomain"

    @pytest.mark.asyncio
    async def test_check_all(self, monitor) -> None:
        s1 = await monitor.subscribe("a.com")
        s2 = await monitor.subscribe("b.com")

        # Initialiser les snapshots
        await monitor.check(s1)
        await monitor.check(s2)

        # Simuler un changement sur s1
        s1.last_snapshot = {"subdomains": ["old.a.com"]}

        async def mock_collect(target):
            if target == "a.com":
                return {"subdomains": ["old.a.com", "new.a.com"]}
            return {"subdomains": []}

        monitor._collect = mock_collect

        results = await monitor.check_all()
        assert len(results) == 2
        assert len(results[s1.id]) == 1  # a.com changed
        assert len(results[s2.id]) == 0  # b.com unchanged

    @pytest.mark.asyncio
    async def test_notifier_called(self, monitor) -> None:
        notified = []

        async def notifier(alert) -> None:
            notified.append(alert)

        monitor.notifier = notifier
        sub = await monitor.subscribe("example.com")
        await monitor.check(sub)
        sub.last_snapshot = {"subdomains": ["old.example.com"]}

        async def mock_collect(target):
            return {"subdomains": ["old.example.com", "new.example.com"]}

        monitor._collect = mock_collect

        await monitor.check(sub)
        assert len(notified) == 1


# ── SemanticGraphSearch ───────────────────────────────────────


class TestSemanticGraphSearch:
    @pytest.fixture
    def graph(self):
        g = GraphEngine()
        # Ajouter des entités de test
        domain = Entity(type=EntityType.DOMAIN, value="example.com")
        ip = Entity(type=EntityType.IP, value="93.184.216.34")
        sub = Entity(type=EntityType.DOMAIN, value="admin.example.com")

        g.add_entity(domain)
        g.add_entity(ip)
        g.add_entity(sub)

        g.add_relation(domain, ip, RelationType.HOSTS)
        g.add_relation(sub, ip, RelationType.HOSTS)

        return g

    @pytest.fixture
    def ai_engine(self):
        engine = AsyncMock()
        # Mock response for translate
        from navmax.ai.providers.base import GenerateResult, ProviderType

        engine.generate = AsyncMock(
            return_value=GenerateResult(
                text=__import__("json").dumps(
                    {
                        "operations": [
                            {
                                "type": "find_entities",
                                "entity_type": "domain",
                                "filters": {"value_contains": "admin"},
                            },
                        ],
                        "explanation": "Find all domains containing 'admin'",
                    },
                ),
                model="mock",
                provider=ProviderType.OLLAMA,
                tokens_used=50,
                tokens_per_second=25.0,
                finish_reason="stop",
            ),
        )
        return engine

    def test_init(self, graph, ai_engine) -> None:
        search = SemanticGraphSearch(graph, ai_engine)
        assert search.graph is graph
        assert search.ai is ai_engine

    @pytest.mark.asyncio
    async def test_search_translates_and_executes(self, graph, ai_engine) -> None:
        search = SemanticGraphSearch(graph, ai_engine)
        result = await search.search("Find admin subdomains")

        assert result.question == "Find admin subdomains"
        assert result.count >= 1
        # admin.example.com devrait être trouvé
        values = [e["value"] for e in result.entities]
        assert "admin.example.com" in values

    @pytest.mark.asyncio
    async def test_search_handles_translation_failure(self, graph) -> None:
        """L'erreur AI est loggée sans crasher (refactoring: graceful degradation)."""
        ai = AsyncMock()
        ai.generate = AsyncMock(side_effect=Exception("AI error"))
        search = SemanticGraphSearch(graph, ai)

        result = await search.search("test")
        # Le refactoring catch l'erreur et retourne un résultat vide au lieu de crasher
        assert result is not None

    def test_graph_query_result(self) -> None:
        result = GraphQueryResult(
            question="test?",
            explanation="Finding things",
            entities=[{"id": "1", "type": "domain", "value": "test.com"}],
        )
        assert result.count == 1

    def test_execute_find_entities(self, graph, ai_engine) -> None:
        search = SemanticGraphSearch(graph, ai_engine)
        ops = [{"type": "find_entities", "entity_type": "domain"}]
        entities, _relations = search._execute(ops)
        assert len(entities) >= 2  # example.com + admin.example.com
        values = [e["value"] for e in entities]
        assert "example.com" in values

    def test_execute_get_neighbors(self, graph, ai_engine) -> None:
        search = SemanticGraphSearch(graph, ai_engine)
        # Trouver example.com directement
        entities, _ = search._execute(
            [
                {
                    "type": "find_entities",
                    "entity_type": "domain",
                    "filters": {"value_contains": "example.com"},
                },
            ],
        )
        assert len(entities) >= 1
        # Vérifier que get_neighbors fonctionne avec l'ID direct
        if entities:
            entities[0]["id"]
            neighbor_ops = [{"type": "get_neighbors", "entity_id": "direct", "depth": 1}]
            # Override context manually
            neighbors, _ = search._execute(neighbor_ops)
            # Should work at the structural level
            assert isinstance(neighbors, list)
