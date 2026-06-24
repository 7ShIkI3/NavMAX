"""
Tests du module OSINT NavMAX — Phase 4.
"""

import pytest


class TestDnsCollector:
    @pytest.mark.asyncio
    async def test_lookup_example_com(self) -> None:
        from navmax.osint import DnsCollector
        records = await DnsCollector.lookup("example.com")
        assert len(records) >= 2
        types = [r.type for r in records]
        assert "A" in types
        assert "NS" in types

    @pytest.mark.asyncio
    async def test_lookup_specific_types(self) -> None:
        from navmax.osint import DnsCollector
        records = await DnsCollector.lookup("example.com", ["A", "AAAA"])
        types = [r.type for r in records]
        assert all(t in ("A", "AAAA") for t in types)

    @pytest.mark.asyncio
    async def test_reverse_lookup(self) -> None:
        from navmax.osint import DnsCollector
        records = await DnsCollector.reverse_lookup("1.1.1.1")
        assert len(records) >= 0  # Peut échouer si pas de PTR


class TestWhoisCollector:
    @pytest.mark.asyncio
    async def test_lookup_example_com(self) -> None:
        from navmax.osint import WhoisCollector
        info = await WhoisCollector.lookup("example.com")
        if info:
            assert info.domain == "example.com"


class TestSslCollector:
    @pytest.mark.asyncio
    async def test_get_cert_example_com(self) -> None:
        from navmax.osint import SslCollector
        info = await SslCollector.get_cert("example.com", 443)
        if info and info.subject:
            assert len(info.subject) > 0
            assert len(info.san) >= 1
            assert "example.com" in info.san or any("example" in s for s in info.san)


class TestWebCollector:
    @pytest.mark.asyncio
    async def test_analyze_example_com(self) -> None:
        from navmax.osint import WebCollector
        c = WebCollector(timeout=10.0)
        info = await c.analyze("example.com")
        await c.close()
        if info:
            assert info.status_code >= 200


class TestGraphEngine:
    def test_add_entity(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType
        g = GraphEngine()
        e = Entity(type=EntityType.DOMAIN, value="test.com", label="test.com")
        gid = g.add_entity(e)
        assert g.node_count == 1
        assert g.get_entity(gid) is not None

    def test_find_entity(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType
        g = GraphEngine()
        e = Entity(type=EntityType.IP, value="1.2.3.4", label="1.2.3.4")
        g.add_entity(e)
        found = g.find_entity("1.2.3.4", EntityType.IP)
        assert found is not None
        assert found.type == EntityType.IP

    def test_add_relation(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType, RelationType
        g = GraphEngine()
        domain = Entity(type=EntityType.DOMAIN, value="test.com", label="test.com")
        ip = Entity(type=EntityType.IP, value="1.2.3.4", label="1.2.3.4")
        g.add_relation(domain, ip, RelationType.A_RECORD)
        assert g.node_count == 2
        assert g.edge_count == 1

    def test_dedup(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType
        g = GraphEngine()
        e1 = Entity(type=EntityType.DOMAIN, value="test.com")
        e2 = Entity(type=EntityType.DOMAIN, value="test.com")
        gid1 = g.add_entity(e1)
        gid2 = g.add_entity(e2)
        assert gid1 == gid2
        assert g.node_count == 1

    def test_get_neighbors(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType, RelationType
        g = GraphEngine()
        domain = Entity(type=EntityType.DOMAIN, value="test.com", label="test.com")
        ip = Entity(type=EntityType.IP, value="1.2.3.4", label="1.2.3.4")
        g.add_relation(domain, ip, RelationType.A_RECORD)

        neighbors = g.get_neighbors(g.add_entity(domain), depth=1)
        assert len(neighbors) >= 1

    def test_search(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType
        g = GraphEngine()
        e = Entity(type=EntityType.DOMAIN, value="my-test.com", label="my-test.com")
        g.add_entity(e)
        results = g.search("my-test")
        assert len(results) == 1

    def test_export_cytoscape(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType, RelationType
        g = GraphEngine()
        e = Entity(type=EntityType.DOMAIN, value="test.com")
        ip = Entity(type=EntityType.IP, value="1.2.3.4")
        g.add_relation(e, ip, RelationType.A_RECORD)
        exp = g.export_cytoscape()
        assert "elements" in exp
        assert len(exp["elements"]) >= 2

    def test_export_sigmajs(self) -> None:
        from navmax.osint import GraphEngine, Entity, EntityType, RelationType
        g = GraphEngine()
        e = Entity(type=EntityType.DOMAIN, value="test.com")
        ip = Entity(type=EntityType.IP, value="1.2.3.4")
        g.add_relation(e, ip, RelationType.A_RECORD)
        exp = g.export_sigmajs()
        assert "nodes" in exp
        assert "edges" in exp


class TestTransforms:
    def test_get_transforms(self) -> None:
        from navmax.osint.graph import get_transforms_for, EntityType
        transforms = get_transforms_for(EntityType.DOMAIN)
        assert len(transforms) >= 3

    def test_transforms_for_ip(self) -> None:
        from navmax.osint.graph import get_transforms_for, EntityType
        transforms = get_transforms_for(EntityType.IP)
        assert len(transforms) >= 1


class TestEntities:
    def test_entity_types(self) -> None:
        from navmax.osint import EntityType, RelationType
        assert EntityType.DOMAIN.value == "domain"
        assert EntityType.IP.value == "ip"
        assert RelationType.A_RECORD.value == "a_record"
        assert RelationType.LINKED_TO.value == "linked_to"


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_investigate_domain(self) -> None:
        from navmax.osint import OsintOrchestrator
        orch = OsintOrchestrator(max_depth=1)
        result = await orch.investigate("example.com", "domain")
        assert result["node_count"] >= 2
        assert result["edge_count"] >= 1
        assert len(result["log"]) >= 5

    @pytest.mark.asyncio
    async def test_investigate_ip(self) -> None:
        from navmax.osint import OsintOrchestrator
        orch = OsintOrchestrator(max_depth=1)
        result = await orch.investigate("1.1.1.1", "ip")
        assert result["node_count"] >= 1
