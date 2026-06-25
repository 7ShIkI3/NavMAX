"""
Moteur central : configuration, logging structuré, moteur de plugins.
"""

from .config import Config, config
from .logging import setup_logging, get_logger
from .plugin_manager import (
    PluginBase,
    PluginManager,
    PluginDescriptor,
    register_plugin,
    make_plugin_api_routes,
)

__all__ = [
    "Config",
    "config",
    "setup_logging",
    "get_logger",
    "PluginBase",
    "PluginManager",
    "PluginDescriptor",
    "register_plugin",
    "make_plugin_api_routes",
]
