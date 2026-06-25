"""
Tests unitaires pour le système de plugins modulaire (navmax/core/plugin_manager.py).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from navmax.core.plugin_manager import (
    PluginBase,
    PluginDescriptor,
    PluginManager,
    _PLUGIN_REGISTRY,
    make_plugin_api_routes,
    register_plugin,
)


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_registry():
    """Nettoie le registre global avant et après chaque test."""
    PluginManager.clear_registry()
    yield
    PluginManager.clear_registry()


@pytest.fixture
def sample_plugin_dir():
    """Crée un répertoire temporaire avec deux plugins factices."""
    with tempfile.TemporaryDirectory(prefix="navmax_plugins_") as tmpdir:
        base = Path(tmpdir)

        # Plugin A : scanner
        scanner_dir = base / "port_scanner"
        scanner_dir.mkdir()
        (scanner_dir / "manifest.json").write_text(
            json.dumps({
                "name": "port_scanner",
                "version": "2.1.0",
                "author": "NavMAX Team",
                "description": "Scan de ports TCP/UDP",
                "category": "scanner",
            }),
            "utf-8",
        )
        (scanner_dir / "plugin.py").write_text(
            """
from navmax.core.plugin_manager import PluginBase, register_plugin

@register_plugin(name="port_scanner", version="2.1.0",
                 author="NavMAX Team", description="Scan de ports TCP/UDP",
                 category="scanner")
class PortScannerPlugin(PluginBase):
    async def execute(self, **kwargs):
        return {"status": "ok", "data": {"ports": [22, 80, 443]}}
""",
            "utf-8",
        )

        # Plugin B : osint
        osint_dir = base / "dns_lookup"
        osint_dir.mkdir()
        (osint_dir / "manifest.json").write_text(
            json.dumps({
                "name": "dns_lookup",
                "version": "1.0.0",
                "author": "OSINT Team",
                "description": "Résolution DNS avancée",
                "category": "osint",
            }),
            "utf-8",
        )
        (osint_dir / "plugin.py").write_text(
            """
from navmax.core.plugin_manager import PluginBase, register_plugin

@register_plugin(name="dns_lookup", version="1.0.0",
                 author="OSINT Team", description="Résolution DNS avancée",
                 category="osint")
class DnsLookupPlugin(PluginBase):
    async def execute(self, **kwargs):
        domain = kwargs.get("domain", "example.com")
        return {"status": "ok", "data": {"domain": domain, "ips": ["93.184.216.34"]}}
""",
            "utf-8",
        )

        yield str(base)


# ── tests du décorateur @register_plugin ─────────────────────────────────────


class TestRegisterPluginDecorator:
    """Tests unitaires pour le décorateur @register_plugin."""

    def test_register_valid_plugin(self):
        @register_plugin(name="test_ping", version="0.1.0", category="scanner")
        class PingPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok", "data": {"alive": True}}

        assert "test_ping" in PluginManager.registered_plugins()
        assert PluginManager.registered_plugins()["test_ping"] is PingPlugin

    def test_register_duplicate_raises(self):
        @register_plugin(name="dup", version="1.0", category="scanner")
        class DupA(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        with pytest.raises(KeyError, match="déjà enregistré"):

            @register_plugin(name="dup", version="2.0", category="osint")
            class DupB(PluginBase):
                async def execute(self, **kwargs):
                    return {"status": "ok"}

    def test_register_non_plugin_base_raises(self):
        with pytest.raises(TypeError, match="sous-classe de PluginBase"):

            @register_plugin(name="bad", version="1.0", category="scanner")
            class NotAPlugin:
                pass

    def test_register_invalid_category_raises(self):
        with pytest.raises(ValueError, match="Catégorie"):

            @register_plugin(name="inv", version="1.0", category="invalid_cat")
            class InvalidCatPlugin(PluginBase):
                async def execute(self, **kwargs):
                    return {"status": "ok"}

    @pytest.mark.parametrize("cat", ["scanner", "exploit", "osint", "proxy", "ad", "firewall", "reporting", "ai"])
    def test_all_valid_categories(self, cat):
        @register_plugin(name=f"plugin_{cat}", version="1.0", category=cat)
        class CatPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        assert f"plugin_{cat}" in PluginManager.registered_plugins()

    def test_metadata_attached(self):
        @register_plugin(
            name="meta_test",
            version="3.0.0",
            author="Test Author",
            description="A test plugin with metadata",
            category="reporting",
        )
        class MetaPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        instance = MetaPlugin()
        assert instance.name == "meta_test"
        assert instance.version == "3.0.0"
        assert instance.author == "Test Author"
        assert instance.description == "A test plugin with metadata"
        assert instance.category == "reporting"

    def test_register_without_author_and_description(self):
        @register_plugin(name="minimal", version="1.0", category="ai")
        class MinimalPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        instance = MinimalPlugin()
        assert instance.name == "minimal"
        assert instance.author == ""
        assert instance.description == ""


# ── tests de PluginBase ──────────────────────────────────────────────────────


class TestPluginBase:
    """Tests unitaires pour la classe de base PluginBase."""

    def test_abstract_execute(self):
        """PluginBase ne peut pas être instanciée directement car execute est abstrait."""
        with pytest.raises(TypeError):
            PluginBase()

    def test_initialize_and_cleanup(self):
        @register_plugin(name="lifecycle", version="1.0", category="scanner")
        class LifecyclePlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        instance = LifecyclePlugin()
        assert instance.initialized is False
        assert instance.instance_id != ""

        # initialize
        import asyncio
        asyncio.run(instance.initialize())
        assert instance.initialized is True

        # cleanup
        asyncio.run(instance.cleanup())
        assert instance.initialized is False

    def test_metadata_dict(self):
        @register_plugin(
            name="meta_dict", version="2.0", author="Alice",
            description="Plugin metadata test", category="exploit",
        )
        class DictPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        instance = DictPlugin()
        meta = instance.metadata()
        assert meta["name"] == "meta_dict"
        assert meta["version"] == "2.0"
        assert meta["author"] == "Alice"
        assert meta["category"] == "exploit"

    def test_unique_instance_ids(self):
        @register_plugin(name="id_test", version="1.0", category="proxy")
        class IdPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        a = IdPlugin()
        b = IdPlugin()
        assert a.instance_id != b.instance_id


# ── tests de PluginManager ───────────────────────────────────────────────────


class TestPluginManagerDiscovery:
    """Tests de la découverte de plugins par dossier."""

    def test_discover_empty_directory(self, tmp_path):
        empty = tmp_path / "empty_plugins"
        empty.mkdir()
        manager = PluginManager()
        discovered = manager.discover_plugins(str(empty))
        assert discovered == []

    def test_discover_nonexistent_directory(self):
        manager = PluginManager()
        discovered = manager.discover_plugins("/tmp/nonexistent_plugins_xyz")
        assert discovered == []

    def test_discover_without_manifest_skipped(self, tmp_path):
        d = tmp_path / "no_manifest"
        d.mkdir()
        (d / "plugin.py").write_text("# no manifest", "utf-8")
        manager = PluginManager()
        discovered = manager.discover_plugins(str(tmp_path))
        assert discovered == []

    def test_discover_invalid_manifest_skipped(self, tmp_path):
        d = tmp_path / "bad_manifest"
        d.mkdir()
        (d / "manifest.json").write_text("not json", "utf-8")
        (d / "plugin.py").write_text("# no valid manifest", "utf-8")
        manager = PluginManager()
        discovered = manager.discover_plugins(str(tmp_path))
        assert discovered == []

    def test_discover_sample_plugins(self, sample_plugin_dir):
        manager = PluginManager()
        discovered = manager.discover_plugins(sample_plugin_dir)
        names = {d.name for d in discovered}
        assert "port_scanner" in names
        assert "dns_lookup" in names
        assert len(discovered) == 2

    def test_discover_fills_descriptors(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        desc = manager._descriptors.get("port_scanner")
        assert desc is not None
        assert desc.version == "2.1.0"
        assert desc.category == "scanner"
        assert desc.author == "NavMAX Team"
        assert desc.loaded is False


class TestPluginManagerLoad:
    """Tests du chargement de plugins."""

    async def test_load_plugin_from_discovery(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        instance = await manager.load_plugin("port_scanner")
        assert instance is not None
        assert instance.name == "port_scanner"
        assert instance.initialized is True

    async def test_load_plugin_from_registry_only(self):
        @register_plugin(name="registry_only", version="1.0", category="ai")
        class RegistryOnlyPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        manager = PluginManager()
        instance = await manager.load_plugin("registry_only")
        assert instance is not None
        assert instance.name == "registry_only"
        assert instance.initialized is True

    async def test_load_nonexistent_plugin(self):
        manager = PluginManager()
        instance = await manager.load_plugin("does_not_exist")
        assert instance is None

    async def test_load_plugin_updates_descriptor(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        desc_before = manager._descriptors["dns_lookup"]
        assert desc_before.loaded is False
        assert desc_before.instance_id == ""

        await manager.load_plugin("dns_lookup")
        assert desc_before.loaded is True
        assert desc_before.instance_id != ""

    async def test_load_twice_returns_same_instance(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        inst1 = await manager.load_plugin("port_scanner")
        inst2 = await manager.load_plugin("port_scanner")
        assert inst1 is inst2


class TestPluginManagerList:
    """Tests de list_plugins()."""

    async def test_list_empty(self):
        manager = PluginManager()
        plugins = manager.list_plugins()
        assert plugins == []

    async def test_list_after_discovery(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        plugins = manager.list_plugins()
        assert len(plugins) == 2
        names = {p["name"] for p in plugins}
        assert names == {"port_scanner", "dns_lookup"}
        for p in plugins:
            assert p["loaded"] is False

    async def test_list_after_load(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        await manager.load_plugin("port_scanner")
        plugins = manager.list_plugins()
        port_scanner = next(p for p in plugins if p["name"] == "port_scanner")
        assert port_scanner["loaded"] is True
        assert port_scanner["instance_id"] != ""

    async def test_list_includes_registry_only(self):
        @register_plugin(name="reg_only_list", version="2.0", category="firewall")
        class RegListPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        manager = PluginManager()
        plugins = manager.list_plugins()
        names = {p["name"] for p in plugins}
        assert "reg_only_list" in names


class TestPluginManagerUnload:
    """Tests du déchargement de plugins."""

    async def test_unload_loaded_plugin(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        await manager.load_plugin("port_scanner")
        result = await manager.unload_plugin("port_scanner")
        assert result is True
        assert "port_scanner" not in manager._loaded

    async def test_unload_nonexistent_plugin(self):
        manager = PluginManager()
        result = await manager.unload_plugin("ghost")
        assert result is False

    async def test_unload_not_loaded_plugin(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        result = await manager.unload_plugin("port_scanner")
        assert result is False

    async def test_unload_resets_descriptor(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        await manager.load_plugin("dns_lookup")
        desc = manager._descriptors["dns_lookup"]
        assert desc.loaded is True
        await manager.unload_plugin("dns_lookup")
        assert desc.loaded is False
        assert desc.instance_id == ""


class TestPluginManagerExecute:
    """Tests de l'exécution des plugins."""

    async def test_execute_loaded_plugin(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        await manager.load_plugin("port_scanner")
        result = await manager.execute_plugin("port_scanner")
        assert result["status"] == "ok"
        assert result["data"]["ports"] == [22, 80, 443]

    async def test_execute_with_kwargs(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        await manager.load_plugin("dns_lookup")
        result = await manager.execute_plugin("dns_lookup", domain="navmax.io")
        assert result["status"] == "ok"
        assert result["data"]["domain"] == "navmax.io"

    async def test_execute_not_loaded_returns_error(self):
        manager = PluginManager()
        result = await manager.execute_plugin("ghost")
        assert result["status"] == "error"
        assert "non chargé" in result["message"]

    async def test_execute_not_initialized_returns_error(self):
        @register_plugin(name="uninit", version="1.0", category="scanner")
        class UninitPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        # Charge via registre (initialize sera appelée), mais on peut forcer un état
        manager = PluginManager()
        instance = await manager.load_plugin("uninit")
        assert instance is not None
        # Ne pas dé-initialiser manuellement, mais si on contourne :
        instance._initialized = False
        result = await manager.execute_plugin("uninit")
        assert result["status"] == "error"
        assert "non initialisé" in result["message"]

    async def test_execute_propagates_exception(self):
        @register_plugin(name="crash", version="1.0", category="scanner")
        class CrashPlugin(PluginBase):
            async def execute(self, **kwargs):
                raise RuntimeError("Boom!")

        manager = PluginManager()
        await manager.load_plugin("crash")
        result = await manager.execute_plugin("crash")
        assert result["status"] == "error"
        assert "Boom!" in result["message"]


class TestPluginManagerIntegration:
    """Tests d'intégration complets du cycle de vie plugin."""

    async def test_full_lifecycle(self, sample_plugin_dir):
        """Découverte → chargement → exécution → déchargement."""
        manager = PluginManager()

        # 1. Découverte
        discovered = manager.discover_plugins(sample_plugin_dir)
        assert len(discovered) == 2

        # 2. Chargement
        scanner = await manager.load_plugin("port_scanner")
        assert scanner is not None
        assert scanner.initialized is True

        # 3. Exécution
        result = await manager.execute_plugin("port_scanner")
        assert result["status"] == "ok"

        # 4. Liste
        listing = manager.list_plugins()
        assert len(listing) == 2
        scanner_info = next(p for p in listing if p["name"] == "port_scanner")
        assert scanner_info["loaded"] is True

        # 5. Déchargement
        unloaded = await manager.unload_plugin("port_scanner")
        assert unloaded is True
        assert scanner.initialized is False

        # 6. Vérification
        listing_after = manager.list_plugins()
        scanner_after = next(p for p in listing_after if p["name"] == "port_scanner")
        assert scanner_after["loaded"] is False

    async def test_multiple_plugins_loaded(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)

        s = await manager.load_plugin("port_scanner")
        d = await manager.load_plugin("dns_lookup")
        assert s is not None
        assert d is not None
        assert len(manager._loaded) == 2

        result_s = await manager.execute_plugin("port_scanner")
        result_d = await manager.execute_plugin("dns_lookup")
        assert result_s["status"] == "ok"
        assert result_d["status"] == "ok"

    async def test_clear_registry_affects_discovery(self):
        @register_plugin(name="will_be_cleared", version="1.0", category="ai")
        class ClearPlugin(PluginBase):
            async def execute(self, **kwargs):
                return {"status": "ok"}

        assert "will_be_cleared" in PluginManager.registered_plugins()
        PluginManager.clear_registry()
        assert "will_be_cleared" not in PluginManager.registered_plugins()


# ── tests de make_plugin_api_routes ─────────────────────────────────────────


class TestPluginAPIRoutes:
    """Tests de la génération des routes API REST."""

    def test_make_plugin_api_routes_returns_router(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        router = make_plugin_api_routes(manager)
        # Pas de test direct des routes FastAPI ici (pas de TestClient),
        # mais on vérifie que c'est bien un APIRouter FastAPI
        from fastapi import APIRouter

        assert isinstance(router, APIRouter)
        assert router.prefix == "/api/v1/plugins"
        assert len(router.routes) == 2

    def test_router_route_names(self):
        manager = PluginManager()
        router = make_plugin_api_routes(manager)
        routes = {r.path for r in router.routes}
        assert "/api/v1/plugins" in routes
        assert "/api/v1/plugins/{name}/execute" in routes

    async def test_router_list_endpoint(self, sample_plugin_dir):
        """Test l'endpoint GET /api/v1/plugins avec le routeur."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)

        app = FastAPI()
        app.include_router(make_plugin_api_routes(manager))

        client = TestClient(app)
        response = client.get("/api/v1/plugins")
        assert response.status_code == 200
        data = response.json()
        assert "plugins" in data
        assert len(data["plugins"]) == 2
        names = {p["name"] for p in data["plugins"]}
        assert names == {"port_scanner", "dns_lookup"}

    async def test_router_execute_endpoint(self, sample_plugin_dir):
        """Test l'endpoint POST /api/v1/plugins/{name}/execute."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        await manager.load_plugin("port_scanner")

        app = FastAPI()
        app.include_router(make_plugin_api_routes(manager))

        client = TestClient(app)
        response = client.post("/api/v1/plugins/port_scanner/execute", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["data"]["ports"] == [22, 80, 443]

    async def test_router_execute_not_loaded_returns_400(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        manager = PluginManager()
        app = FastAPI()
        app.include_router(make_plugin_api_routes(manager))

        client = TestClient(app)
        response = client.post("/api/v1/plugins/nonexistent/execute", json={})
        assert response.status_code == 400
        data = response.json()
        assert "non chargé" in data["message"]


# ── tests de sécurité / robustesse ──────────────────────────────────────────


class TestPluginManagerRobustness:
    """Tests de robustesse et cas limites."""

    def test_discover_plugin_symlink_loop(self, tmp_path):
        """Les liens symboliques ne doivent pas causer d'erreur."""
        d = tmp_path / "plugins"
        d.mkdir()
        # Créer un lien symbolique vers un dossier valide
        real = d / "real_plugin"
        real.mkdir()
        (real / "manifest.json").write_text('{"name":"real"}', "utf-8")
        (real / "plugin.py").write_text("# real", "utf-8")

        # Symlink circulaire
        loop = d / "loop"
        try:
            os.symlink(tmp_path, loop)  # lien vers le parent
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this platform")

        manager = PluginManager()
        discovered = manager.discover_plugins(str(d))
        # Le lien symbolique peut être ignoré ou générer une erreur silencieuse
        # L'important est que ça ne crash pas
        assert len(discovered) >= 1

    @pytest.mark.parametrize("bad_json", ["", "not json", "{broken", "[]"])
    def test_invalid_manifest_does_not_crash(self, tmp_path, bad_json):
        d = tmp_path / "bad"
        d.mkdir()
        (d / "manifest.json").write_text(bad_json, "utf-8")
        (d / "plugin.py").write_text("# test", "utf-8")
        manager = PluginManager()
        discovered = manager.discover_plugins(str(tmp_path))
        assert len(discovered) == 0

    async def test_load_plugin_with_missing_file_returns_none(self, sample_plugin_dir):
        manager = PluginManager()
        manager.discover_plugins(sample_plugin_dir)
        # Supprimer le fichier plugin.py
        desc = manager._descriptors["port_scanner"]
        os.remove(Path(desc.path) / "plugin.py")
        instance = await manager.load_plugin("port_scanner")
        assert instance is None

    async def test_cleanup_on_unload_not_crashing(self):
        @register_plugin(name="messy", version="1.0", category="scanner")
        class MessyPlugin(PluginBase):
            async def cleanup(self):
                raise RuntimeError("Cleanup fails but should not crash")

            async def execute(self, **kwargs):
                return {"status": "ok"}

        manager = PluginManager()
        await manager.load_plugin("messy")
        result = await manager.unload_plugin("messy")
        assert result is True  # Even though cleanup raised
        assert "messy" not in manager._loaded

    def test_make_api_routes_empty_manager(self):
        manager = PluginManager()
        router = make_plugin_api_routes(manager)
        assert router.prefix == "/api/v1/plugins"

    @pytest.mark.parametrize("cat", ["scanner", "exploit", "osint"])
    def test_descriptor_creation(self, cat):
        desc = PluginDescriptor(
            name="test",
            version="1.0",
            author="Tester",
            description="A test",
            category=cat,
            path="/tmp/test",
        )
        assert desc.name == "test"
        assert desc.category == cat
        assert desc.loaded is False

    def test_descriptor_extra_fields(self):
        desc = PluginDescriptor(
            name="test", version="1.0", author="", description="",
            category="scanner", path="/tmp/test",
            extra={"requires": ["nmap"]},
        )
        assert desc.extra["requires"] == ["nmap"]

    def test_descriptor_defaults(self):
        desc = PluginDescriptor(
            name="min", version="1.0", author="", description="",
            category="scanner", path="/tmp/min",
        )
        assert desc.loaded is False
        assert desc.instance_id == ""
        assert desc.extra == {}


# ── test que PluginManager est accessible depuis l'API publique ──────────────


def test_public_api_imports():
    """Vérifie que les symboles sont bien dans le namespace attendu."""
    from navmax.core import (
        PluginBase as PB,
        PluginManager as PM,
        PluginDescriptor as PD,
        register_plugin as RP,
        make_plugin_api_routes as MR,
    )

    assert PB is PluginBase
    assert PM is PluginManager
    assert PD is PluginDescriptor
    assert RP is register_plugin
    assert MR is make_plugin_api_routes
