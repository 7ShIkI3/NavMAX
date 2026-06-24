"""NavMAX AI — Moteur IA multi-provider avec sélection automatique."""

from navmax.ai.engine import AIEngine, get_engine
from navmax.ai.hardware import detect_hardware, HardwareProfile
from navmax.ai.selector import ModelSelector, SelectionResult, SelectionReport
from navmax.ai.providers.base import (
    ModelTier, ProviderType, ModelInfo,
    GenerateParams, GenerateResult, BaseProvider,
)
from navmax.ai.models_catalog import (
    MODEL_CATALOG, CatalogEntry, ModelTag,
    get_abliterated_models, get_recommended, find_best_for_task,
)

__all__ = [
    # Engine
    "AIEngine", "get_engine",
    # Hardware
    "detect_hardware", "HardwareProfile",
    # Selector
    "ModelSelector", "SelectionResult", "SelectionReport",
    # Base types
    "ModelTier", "ProviderType", "ModelInfo",
    "GenerateParams", "GenerateResult", "BaseProvider",
    # Catalog
    "MODEL_CATALOG", "CatalogEntry", "ModelTag",
    "get_abliterated_models", "get_recommended", "find_best_for_task",
]
