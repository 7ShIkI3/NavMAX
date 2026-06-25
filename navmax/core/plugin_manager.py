"""
Système de plugins modulaire pour NavMAX.
===========================================

Découverte par dossier (~/.navmax/plugins/<nom>/plugin.py + manifest.json),
décorateur @register_plugin, cycle de vie initialize/execute/cleanup,
et intégration API REST.

Catégories supportées : scanner, exploit, osint, proxy, ad, firewall, reporting, ai.
"""

from __future__ import annotations

import abc
import importlib.util
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# ── registre global (peuplé par le décorateur @register_plugin) ──────────────
_PLUGIN_REGISTRY: dict[str, type["PluginBase"]] = {}


def register_plugin(
    *,
    name: str,
    version: str,
    author: str = "",
    description: str = "",
    category: str = "",
) -> Callable[[type["PluginBase"]], type["PluginBase"]]:
    """Décorateur : enregistre une classe de plugin dans le registre global.

    Args:
        name: Nom unique du plugin.
        version: Version sémantique.
        author: Auteur.
        description: Description courte.
        category: Catégorie (scanner, exploit, osint, proxy, ad, firewall, reporting, ai).

    Usage::

        @register_plugin(name="nmap", version="1.0", category="scanner")
        class NmapPlugin(PluginBase):
            ...

    La classe doit hériter de *PluginBase*.
    """
    VALID_CATEGORIES = {"scanner", "exploit", "osint", "proxy", "ad", "firewall", "reporting", "ai"}
    if category and category not in VALID_CATEGORIES:
        raise ValueError(
            f"Catégorie '{category}' invalide. "
            f"Choisir parmi : {', '.join(sorted(VALID_CATEGORIES))}"
        )

    def _decorator(cls: type["PluginBase"]) -> type["PluginBase"]:
        if not issubclass(cls, PluginBase):
            raise TypeError(f"@{register_plugin.__name__} ne peut être appliqué qu'à une sous-classe de PluginBase.")
        if name in _PLUGIN_REGISTRY:
            raise KeyError(f"Un plugin nommé '{name}' est déjà enregistré.")
        # Attacher les métadonnées comme attributs de classe
        cls._meta_name = name
        cls._meta_version = version
        cls._meta_author = author
        cls._meta_description = description
        cls._meta_category = category
        _PLUGIN_REGISTRY[name] = cls
        return cls

    return _decorator


# ── classe de base abstraite ─────────────────────────────────────────────────


class PluginBase(abc.ABC):
    """Classe de base que tout plugin NavMAX doit étendre.

    Fournit le cycle de vie standard : initialize → execute → cleanup.
    Les métadonnées (name, version, …) sont définies via @register_plugin.
    """

    # Métadonnées – injectées par le décorateur
    _meta_name: str = ""
    _meta_version: str = ""
    _meta_author: str = ""
    _meta_description: str = ""
    _meta_category: str = ""

    def __init__(self) -> None:
        self._instance_id: str = uuid.uuid4().hex[:12]
        self._initialized: bool = False

    # ── propriétés exposées ──────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return self._meta_name

    @property
    def version(self) -> str:
        return self._meta_version

    @property
    def author(self) -> str:
        return self._meta_author

    @property
    def description(self) -> str:
        return self._meta_description

    @property
    def category(self) -> str:
        return self._meta_category

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @property
    def initialized(self) -> bool:
        return self._initialized

    def metadata(self) -> dict[str, str]:
        """Retourne un dictionnaire des métadonnées du plugin."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "category": self.category,
        }

    # ── cycle de vie ─────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Initialisation asynchrone du plugin (connexions DB, clients HTTP, …)."""
        self._initialized = True

    @abc.abstractmethod
    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Point d'entrée principal du plugin.

        Returns:
            Dictionnaire avec au moins les clés ``status`` et ``data``.
            Exemple : {"status": "ok", "data": {...}}.
        """

    async def cleanup(self) -> None:
        """Nettoyage asynchrone (fermeture connexions, libération ressources)."""
        self._initialized = False


# ── helpers de chargement de module depuis un fichier ────────────────────────


def _load_module_from_path(module_path: str | Path) -> Any:
    """Importe un module Python depuis un chemin fichier absolu.

    Retourne le module importé, ou lève une exception en cas d'échec.
    """
    module_path = Path(module_path).resolve()
    if not module_path.exists():
        raise FileNotFoundError(f"Plugin introuvable : {module_path}")

    # Nom de module unique basé sur le chemin absolu pour éviter les collisions
    stem = module_path.stem  # ex. "plugin"
    mod_name = f"_navmax_plugin_{stem}_{uuid.uuid4().hex[:8]}"

    spec = importlib.util.spec_from_file_location(mod_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Impossible de créer un spec pour {module_path}")

    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ── PluginManager ────────────────────────────────────────────────────────────


@dataclass
class PluginDescriptor:
    """Informations sur un plugin découvert, qu'il soit chargé ou non."""

    name: str
    version: str
    author: str
    description: str
    category: str
    path: str  # chemin absolu du dossier plugin
    loaded: bool = False
    instance_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class PluginManager:
    """Gestionnaire principal de plugins NavMAX.

    Responsabilités :

    * découvrir les plugins depuis un dossier de type ``~/.navmax/plugins/<nom>/``
      (via ``manifest.json`` + ``plugin.py``)
    * charger / décharger des plugins dynamiquement
    * lister les plugins avec leurs métadonnées
    * intégration API REST (``GET /api/v1/plugins``, ``POST /api/v1/plugins/{name}/execute``)
    """

    def __init__(self) -> None:
        self._loaded: dict[str, PluginBase] = {}  # name -> instance chargée
        self._descriptors: dict[str, PluginDescriptor] = {}  # name -> descripteur

    # ── découverte ───────────────────────────────────────────────────────────

    def discover_plugins(self, plugin_dir: str) -> list[PluginDescriptor]:
        """Scanne *plugin_dir* à la recherche de sous-dossiers de plugins.

        Chaque sous-dossier doit contenir un fichier ``manifest.json`` et un fichier
        ``plugin.py`` pour être reconnu.

        Returns:
            Liste des descripteurs de plugins découverts.
        """
        base = Path(plugin_dir).expanduser().resolve()
        if not base.is_dir():
            return []

        discovered: list[PluginDescriptor] = []

        for entry in sorted(base.iterdir()):
            if not entry.is_dir():
                continue
            manifest_path = entry / "manifest.json"
            plugin_py_path = entry / "plugin.py"
            if not manifest_path.is_file() or not plugin_py_path.is_file():
                continue

            # Lire le manifeste
            try:
                manifest = json.loads(manifest_path.read_text("utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            name = manifest.get("name", entry.name)
            descriptor = PluginDescriptor(
                name=name,
                version=manifest.get("version", "0.0.0"),
                author=manifest.get("author", ""),
                description=manifest.get("description", ""),
                category=manifest.get("category", ""),
                path=str(entry),
                extra=manifest.get("extra", {}),
            )
            self._descriptors[name] = descriptor
            discovered.append(descriptor)

        return discovered

    # ── chargement ───────────────────────────────────────────────────────────

    async def load_plugin(self, name: str) -> PluginBase | None:
        """Charge un plugin préalablement découvert par son *name*.

        Étapes :
        1. Recherche le descripteur (découvert ou issu du registre global).
        2. Importe ``plugin.py``.
        3. Instancie la classe enregistrée via ``@register_plugin``.
        4. Appelle ``initialize()``.
        5. Stocke l'instance dans ``_loaded``.

        Returns:
            L'instance du plugin, ou ``None`` en cas d'échec.
        """
        # 1. Descripteur connu ?
        desc = self._descriptors.get(name)
        if desc is None:
            # Tenter un chargement direct depuis le registre (utile pour les tests)
            if name in _PLUGIN_REGISTRY:
                cls = _PLUGIN_REGISTRY[name]
                instance = cls()
                await instance.initialize()
                self._loaded[name] = instance
                return instance
            return None

        # 2. Importer plugin.py
        plugin_py = Path(desc.path) / "plugin.py"
        if not plugin_py.is_file():
            return None

        try:
            mod = _load_module_from_path(plugin_py)
        except (ImportError, FileNotFoundError) as exc:
            # fallback : peut-être que la classe vient du registre déjà importé
            if name in _PLUGIN_REGISTRY:
                cls = _PLUGIN_REGISTRY[name]
                instance = cls()
                await instance.initialize()
                self._loaded[name] = instance
                return instance
            return None

        # 3. Chercher la classe enregistrée dans ce module
        plugin_cls = _PLUGIN_REGISTRY.get(name)
        if plugin_cls is None:
            return None

        # 4. Instancier
        instance = plugin_cls()
        try:
            await instance.initialize()
        except Exception:
            return None

        self._loaded[name] = instance
        desc.loaded = True
        desc.instance_id = instance.instance_id
        return instance

    # ── liste ────────────────────────────────────────────────────────────────

    def list_plugins(self) -> list[dict[str, Any]]:
        """Liste tous les plugins disponibles avec leurs métadonnées.

        Returns:
            Liste de dictionnaires contenant les métadonnées et l'état de chaque plugin.
        """
        result: list[dict[str, Any]] = []

        # Plugins découverts par dossier
        seen: set[str] = set()
        for desc in self._descriptors.values():
            seen.add(desc.name)
            result.append({
                "name": desc.name,
                "version": desc.version,
                "author": desc.author,
                "description": desc.description,
                "category": desc.category,
                "loaded": desc.loaded,
                "instance_id": desc.instance_id,
                "path": desc.path,
                "extra": desc.extra,
            })

        # Plugins dans le registre global mais pas (encore) découverts par dossier
        for reg_name, cls in _PLUGIN_REGISTRY.items():
            if reg_name in seen:
                continue
            loaded = reg_name in self._loaded
            instance_id = ""
            if loaded:
                instance_id = self._loaded[reg_name].instance_id
            result.append({
                "name": reg_name,
                "version": getattr(cls, "_meta_version", ""),
                "author": getattr(cls, "_meta_author", ""),
                "description": getattr(cls, "_meta_description", ""),
                "category": getattr(cls, "_meta_category", ""),
                "loaded": loaded,
                "instance_id": instance_id,
                "path": "",
                "extra": {},
            })

        return result

    # ── déchargement ─────────────────────────────────────────────────────────

    async def unload_plugin(self, name: str) -> bool:
        """Décharge un plugin par son nom.

        Appelle ``cleanup()`` sur l'instance avant de la retirer.

        Returns:
            ``True`` si le plugin a été déchargé, ``False`` s'il n'était pas chargé.
        """
        instance = self._loaded.pop(name, None)
        if instance is None:
            return False
        try:
            await instance.cleanup()
        except Exception:
            pass  # ne pas bloquer le déchargement
        # Mettre à jour le descripteur si présent
        desc = self._descriptors.get(name)
        if desc is not None:
            desc.loaded = False
            desc.instance_id = ""
        return True

    # ── exécution (utilisé par l'API) ────────────────────────────────────────

    async def execute_plugin(self, name: str, **kwargs: Any) -> dict[str, Any]:
        """Exécute un plugin précédemment chargé.

        Args:
            name: Nom du plugin.
            **kwargs: Arguments passés à ``execute()``.

        Returns:
            Résultat de ``execute()``, ou dictionnaire d'erreur.
        """
        instance = self._loaded.get(name)
        if instance is None:
            return {"status": "error", "message": f"Plugin '{name}' non chargé."}
        if not instance.initialized:
            return {"status": "error", "message": f"Plugin '{name}' non initialisé."}
        try:
            result = await instance.execute(**kwargs)
            return result
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    # ── hooks pour le registre global ───────────────────────────────────────

    @classmethod
    def registered_plugins(cls) -> dict[str, type["PluginBase"]]:
        """Retourne une copie du registre global (lecture seule)."""
        return dict(_PLUGIN_REGISTRY)

    @classmethod
    def clear_registry(cls) -> None:
        """Vide le registre global (utile pour les tests)."""
        _PLUGIN_REGISTRY.clear()


# ── helpers d'intégration API REST ───────────────────────────────────────────


def make_plugin_api_routes(manager: PluginManager) -> list[dict[str, Any]]:
    """Génère les définitions de routes REST pour FastAPI à partir du manager.

    Returns:
        Liste de dictionnaires utilisables comme routes FastAPI.
        Chaque dict contient ``method``, ``path``, ``handler``, ``summary``.

    Usage::

        manager = PluginManager()
        manager.discover_plugins("~/.navmax/plugins")
        for route in make_plugin_api_routes(manager):
            app.add_api_route(**route)
    """
    from fastapi import APIRouter

    router = APIRouter(prefix="/api/v1/plugins", tags=["plugins"])

    @router.get("", summary="Liste tous les plugins disponibles")
    async def list_plugins():
        return {"plugins": manager.list_plugins()}

    @router.post("/{name}/execute", summary="Exécute un plugin par son nom")
    async def execute_plugin(name: str, payload: dict[str, Any] | None = None):
        result = await manager.execute_plugin(name, **(payload or {}))
        if result.get("status") == "error":
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=400, content=result)
        return result

    return router
