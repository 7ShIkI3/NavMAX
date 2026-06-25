"""Provider OpenAI-compatible — OpenAI, Anthropic, DeepSeek, et tout autre
backend exposant une API /chat/completions compatible OpenAI."""

import asyncio
import json
import time
from typing import AsyncIterator
import aiohttp
import structlog

from navmax.ai.providers.base import (
    BaseProvider, ProviderType, ModelTier, ModelInfo,
    GenerateParams, GenerateResult,
)

logger = structlog.get_logger(__name__)


class OpenAICompatProvider(BaseProvider):
    """Provider générique pour toute API compatible OpenAI."""

    def __init__(self, provider_type: ProviderType, base_url: str,
                 api_key: str, timeout: int = 120):
        self.provider_type = provider_type
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._models: list[ModelInfo] | None = None

    async def health_check(self) -> bool:
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with s.get(
                    f"{self.base_url}/models",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except aiohttp.ClientError:
            return False
        except asyncio.TimeoutError:
            return False

    async def list_models(self) -> list[ModelInfo]:
        if self._models:
            return self._models

        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with s.get(
                    f"{self.base_url}/models",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    self._models = [
                        ModelInfo(
                            name=m["id"],
                            provider=self.provider_type,
                            tier=self._guess_tier(m["id"]),
                            context_window=8192,
                            supports_streaming=True,
                            supports_tools=True,
                        )
                        for m in data.get("data", [])
                    ]
                    return self._models
        except aiohttp.ClientResponseError as e:
            logger.error("openai_list_models_http_error",
                         provider=self.provider_type.value, status=e.status)
            raise RuntimeError(f"HTTP {e.status}: {e.message}") from e
        except aiohttp.ClientError as e:
            logger.error("openai_list_models_client_error",
                         provider=self.provider_type.value, error=str(e))
            raise RuntimeError(f"Connexion échouée: {e}") from e

    def _guess_tier(self, name: str) -> ModelTier:
        n = name.lower()
        # Heavy
        if any(s in n for s in ["gpt-4o", "gpt-4.5", "claude-3-opus",
                                 "claude-3.5", "claude-sonnet-4",
                                 "deepseek-v4-pro", "deepseek-reasoner",
                                 "o1", "o3", "gemini-2.0-pro"]):
            return ModelTier.HEAVY
        if any(s in n for s in ["gpt-4-", "gpt-4 "]):
            return ModelTier.HEAVY
        # Medium (inclut les versions flash/lite)
        if any(s in n for s in ["gpt-3.5", "claude-3-haiku", "deepseek-chat",
                                 "deepseek-v4-flash", "deepseek-v4",
                                 "gemini-2.0-flash", "gpt-4o-mini"]):
            return ModelTier.MEDIUM
        # Light (fast/cheap models)
        if any(s in n for s in ["gpt-4o-mini"]):
            return ModelTier.LIGHT
        return ModelTier.MEDIUM

    async def generate(self, params: GenerateParams) -> GenerateResult:
        t0 = time.monotonic()
        model = params.model or "gpt-4o-mini"

        messages = []
        if params.system:
            messages.append({"role": "system", "content": params.system})
        messages.append({"role": "user", "content": params.prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": params.max_tokens,
            "temperature": params.temperature,
        }
        if params.json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    elapsed = time.monotonic() - t0
                    choice = data["choices"][0]
                    usage = data.get("usage", {})
                    msg = choice["message"]

                    # Handle reasoning_content (DeepSeek R1/V4 style)
                    text = msg.get("content", "")
                    reasoning = msg.get("reasoning_content", "")

                    # If content is empty but reasoning exists (truncated thinking),
                    # return the reasoning as the response
                    if not text and reasoning:
                        text = f"[REASONING]\n{reasoning}"

                    return GenerateResult(
                        text=text,
                        model=model,
                        provider=self.provider_type,
                        tokens_used=usage.get("total_tokens", 0),
                        tokens_per_second=usage.get("total_tokens", 0) / max(elapsed, 0.01),
                        finish_reason=choice.get("finish_reason", "stop"),
                    )
        except asyncio.TimeoutError as e:
            logger.error("openai_generate_timeout",
                         provider=self.provider_type.value, model=model, timeout=self.timeout)
            raise RuntimeError(
                f"Provider '{self.provider_type.value}' timed out after {self.timeout}s"
            ) from e
        except aiohttp.ClientResponseError as e:
            logger.error("openai_generate_http_error",
                         provider=self.provider_type.value, model=model, status=e.status)
            raise RuntimeError(f"HTTP {e.status}: {e.message}") from e
        except aiohttp.ClientError as e:
            logger.error("openai_generate_client_error",
                         provider=self.provider_type.value, model=model, error=str(e))
            raise RuntimeError(f"Connexion échouée: {e}") from e

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        model = params.model or "gpt-4o-mini"

        messages = []
        if params.system:
            messages.append({"role": "system", "content": params.system})
        messages.append({"role": "user", "content": params.prompt})

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": params.max_tokens,
            "temperature": params.temperature,
            "stream": True,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.content:
                        line = line.decode("utf-8").strip()
                        if line.startswith("data: ") and line != "data: [DONE]":
                            try:
                                chunk = json.loads(line[6:])
                                delta = chunk["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
                            except (json.JSONDecodeError, KeyError, IndexError):
                                continue
        except aiohttp.ClientResponseError as e:
            logger.error("openai_stream_http_error",
                         provider=self.provider_type.value, model=model, status=e.status)
            raise RuntimeError(f"HTTP {e.status}: {e.message}") from e
        except aiohttp.ClientError as e:
            logger.error("openai_stream_client_error",
                         provider=self.provider_type.value, model=model, error=str(e))
            raise RuntimeError(f"Connexion échouée: {e}") from e
