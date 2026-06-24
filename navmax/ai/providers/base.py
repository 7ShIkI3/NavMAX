"""Protocol abstrait pour tous les backends LLM."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional
from enum import Enum


class ModelTier(str, Enum):
    """Niveau de capacité du modèle."""
    LIGHT = "light"    # 1-3B — classification, extraction, validation, routage
    MEDIUM = "medium"  # 7-8B — planification, analyse, résumé, traduction
    HEAVY = "heavy"    # 70B+ — génération de code, raisonnement complexe, debug


class ProviderType(str, Enum):
    """Type de provider LLM."""
    OLLAMA = "ollama"
    LLAMACPP = "llamacpp"
    LMSTUDIO = "lmstudio"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"


@dataclass
class ModelInfo:
    """Métadonnées d'un modèle."""
    name: str
    provider: ProviderType
    tier: ModelTier
    context_window: int = 8192
    supports_streaming: bool = True
    supports_tools: bool = False


@dataclass
class GenerateParams:
    """Paramètres d'une requête de génération."""
    prompt: str
    system: Optional[str] = None
    max_tokens: int = 2048
    temperature: float = 0.7
    stop_sequences: list[str] = field(default_factory=list)
    json_mode: bool = False
    model: Optional[str] = None


@dataclass
class GenerateResult:
    """Résultat d'une génération."""
    text: str
    model: str
    provider: ProviderType
    tokens_used: int
    tokens_per_second: float
    finish_reason: str  # "stop", "length", "error"


class BaseProvider(ABC):
    """Interface abstraite pour tous les backends LLM.

    Chaque provider (Ollama, llama.cpp, OpenAI, etc.) implémente cette interface.
    """

    provider_type: ProviderType

    @abstractmethod
    async def generate(self, params: GenerateParams) -> GenerateResult:
        """Génération single-turn."""

    @abstractmethod
    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        """Génération streaming, yield des chunks de texte."""

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Liste les modèles disponibles via ce provider."""

    @abstractmethod
    async def health_check(self) -> bool:
        """True si le provider est accessible."""

    def count_tokens(self, text: str, model: str = "") -> int:
        """Comptage de tokens (heuristique par défaut: ~4 chars/token)."""
        return max(1, len(text) // 4)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass
