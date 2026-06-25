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
from .exceptions import (
    NavMaxError,
    ConfigurationError,
    ValidationError,
    NetworkError,
    NetworkTimeoutError,
    ScanError,
    ExploitError,
    ProxyError,
    ADError,
    AIError,
    PluginError,
)
from .retry import async_retry

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
    # Exceptions
    "NavMaxError",
    "ConfigurationError",
    "ValidationError",
    "NetworkError",
    "NetworkTimeoutError",
    "ScanError",
    "ExploitError",
    "ProxyError",
    "ADError",
    "AIError",
    "PluginError",
    # Utilities
    "async_retry",
]
