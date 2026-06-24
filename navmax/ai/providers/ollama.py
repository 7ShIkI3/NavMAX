"""Ollama provider — backend local par défaut.

Endpoint: http://localhost:11434/api/generate
Install: winget install Ollama.Ollama
"""

import json
import time
import aiohttp
from typing import AsyncIterator
import structlog

from navmax.ai.providers.base import (
    BaseProvider, ProviderType, ModelTier, ModelInfo,
    GenerateParams, GenerateResult,
)

logger = structlog.get_logger(__name__)

# Mapping connu des modèles Ollama → tier
OLLAMA_TIER_MAP: dict[str, ModelTier] = {
    # Light
    "llama3.2:3b": ModelTier.LIGHT,
    "qwen2.5:3b": ModelTier.LIGHT,
    "phi3:3.8b": ModelTier.LIGHT,
    "phi3:mini": ModelTier.LIGHT,
    "gemma2:2b": ModelTier.LIGHT,
    # Medium
    "llama3.1:8b": ModelTier.MEDIUM,
    "mistral:7b": ModelTier.MEDIUM,
    "qwen2.5:7b": ModelTier.MEDIUM,
    "gemma2:9b": ModelTier.MEDIUM,
    "deepseek-r1:8b": ModelTier.MEDIUM,
    "codellama:7b": ModelTier.MEDIUM,
    # Abliterated Medium
    "huihui_ai/llama3.1-abliterated:8b": ModelTier.MEDIUM,
    "huihui_ai/deepseek-r1-abliterated:8b": ModelTier.MEDIUM,
    "huihui_ai/mistral-7b-instruct-abliterated:7b": ModelTier.MEDIUM,
    # Heavy
    "llama3.1:70b": ModelTier.HEAVY,
    "codellama:70b": ModelTier.HEAVY,
    "deepseek-r1:70b": ModelTier.HEAVY,
    "qwen2.5:72b": ModelTier.HEAVY,
    # Abliterated Heavy
    "huihui_ai/llama3.1-abliterated:70b": ModelTier.HEAVY,
}


class OllamaProvider(BaseProvider):
    """Provider Ollama — API HTTP locale."""

    provider_type = ProviderType.OLLAMA

    def __init__(self, base_url: str = "http://localhost:11434", timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._model_cache: list[ModelInfo] | None = None

    async def health_check(self) -> bool:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"{self.base_url}/api/tags", timeout=5) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def list_models(self) -> list[ModelInfo]:
        if self._model_cache:
            return self._model_cache

        async with aiohttp.ClientSession() as s:
            async with s.get(f"{self.base_url}/api/tags", timeout=10) as resp:
                data = await resp.json()
                models = []
                for m in data.get("models", []):
                    name = m["name"]
                    tier = self._guess_tier(name)
                    models.append(ModelInfo(
                        name=name,
                        provider=ProviderType.OLLAMA,
                        tier=tier,
                        context_window=8192,
                        supports_streaming=True,
                    ))
                self._model_cache = models
                return models

    def _guess_tier(self, model_name: str) -> ModelTier:
        # Match exact
        if model_name in OLLAMA_TIER_MAP:
            return OLLAMA_TIER_MAP[model_name]

        # Match base (sans tag)
        base = model_name.split(":")[0]
        for known, tier in OLLAMA_TIER_MAP.items():
            if known.split(":")[0] == base:
                return tier

        # Heuristique par taille dans le nom
        n = model_name.lower()
        if any(s in n for s in ["3b", "1b", "mini", "tiny", "small"]):
            return ModelTier.LIGHT
        if any(s in n for s in ["7b", "8b", "9b", "13b"]):
            return ModelTier.MEDIUM
        if any(s in n for s in ["70b", "72b", "405b"]):
            return ModelTier.HEAVY

        return ModelTier.MEDIUM  # défaut safe

    async def generate(self, params: GenerateParams) -> GenerateResult:
        t0 = time.monotonic()
        model = params.model or "llama3.1:8b"

        payload = {
            "model": model,
            "prompt": params.prompt,
            "stream": False,
            "options": {
                "num_predict": params.max_tokens,
                "temperature": params.temperature,
            }
        }
        if params.system:
            payload["system"] = params.system
        if params.json_mode:
            payload["format"] = "json"
        if params.stop_sequences:
            payload["options"]["stop"] = params.stop_sequences

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                elapsed = time.monotonic() - t0
                eval_count = data.get("eval_count", 0)

                return GenerateResult(
                    text=data.get("response", ""),
                    model=model,
                    provider=ProviderType.OLLAMA,
                    tokens_used=eval_count,
                    tokens_per_second=eval_count / max(elapsed, 0.01),
                    finish_reason="stop" if data.get("done") else "length",
                )

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        model = params.model or "llama3.1:8b"

        payload = {
            "model": model,
            "prompt": params.prompt,
            "stream": True,
            "options": {
                "num_predict": params.max_tokens,
                "temperature": params.temperature,
            }
        }
        if params.system:
            payload["system"] = params.system
        if params.json_mode:
            payload["format"] = "json"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                resp.raise_for_status()
                async for line in resp.content:
                    if line:
                        try:
                            chunk = json.loads(line)
                            if chunk.get("done"):
                                break
                            yield chunk.get("response", "")
                        except json.JSONDecodeError:
                            continue
