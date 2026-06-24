"""
Moteur central : configuration, logging structuré, moteur de plugins.
"""

from .config import Config, config
from .logging import setup_logging, get_logger
from .plugins import PluginManager

__all__ = ["Config", "config", "setup_logging", "get_logger", "PluginManager"]
