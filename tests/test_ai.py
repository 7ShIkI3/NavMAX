"""
Tests pour le module AI de NavMAX.

Couvre :
- HardwareProfile (logique de tiers sans vrai hardware)
- ModelCatalog (recherche, filtrage abliterated)
- ModelSelector (scan, sélection, fallback)
- BaseProvider (protocol)
- AIEngine (orchestration)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from navmax.ai.providers.base import (
    ModelTier, ProviderType, ModelInfo,
    GenerateParams, GenerateResult, BaseProvider,
)
from navmax.ai.hardware import HardwareProfile
from navmax.ai.models_catalog import (
    MODEL_CATALOG, CatalogEntry, ModelTag,
    get_catalog_by_tier, get_abliterated_models,
    get_recommended, match_ollama_model, find_best_for_task,
)
from navmax.ai.selector import ModelSelector, SelectionResult


# ═══════════════════════════════════════════════════════════════════
# Mock Provider pour les tests
# ═══════════════════════════════════════════════════════════════════

class MockProvider(BaseProvider):
    """Provider simulé pour les tests."""

    provider_type = ProviderType.OLLAMA

    def __init__(self, models: list[ModelInfo] = None, healthy: bool = True):
        self._models = models or []
        self._healthy = healthy

    async def generate(self, params: GenerateParams) -> GenerateResult:
        return GenerateResult(
            text=f"mock: {params.prompt[:30]}",
            model=params.model or "mock",
            provider=self.provider_type,
            tokens_used=5,
            tokens_per_second=10.0,
            finish_reason="stop",
        )

    async def stream(self, params: GenerateParams):
        yield "mock "
        yield "response"

    async def list_models(self) -> list[ModelInfo]:
        return self._models

    async def health_check(self) -> bool:
        return self._healthy


def make_model(name: str, provider: ProviderType = ProviderType.OLLAMA,
               tier: ModelTier = ModelTier.MEDIUM) -> ModelInfo:
    return ModelInfo(name=name, provider=provider, tier=tier)


# ═══════════════════════════════════════════════════════════════════
# HardwareProfile
# ═══════════════════════════════════════════════════════════════════

class TestHardwareProfile:
    def test_4gb_ram(self):
        hw = HardwareProfile(os_name="Windows", ram_total_gb=4.0, cpu_cores=2)
        assert hw.can_run_light is True
        assert hw.can_run_medium is False
        assert hw.can_run_heavy is False
        assert hw.max_local_tier == "light"

    def test_8gb_ram(self):
        hw = HardwareProfile(os_name="Linux", ram_total_gb=8.0, cpu_cores=4)
        assert hw.can_run_light is True
        assert hw.can_run_medium is True
        assert hw.can_run_heavy is False
        assert hw.max_local_tier == "medium"

    def test_16gb_ram(self):
        hw = HardwareProfile(os_name="Windows", ram_total_gb=16.0, cpu_cores=8)
        assert hw.can_run_medium is True
        assert hw.can_run_heavy is False
        assert hw.max_local_tier == "medium"

    def test_32gb_with_gpu(self):
        hw = HardwareProfile(
            os_name="Windows", ram_total_gb=32.0,
            gpu_name="RTX 4090", gpu_vram_gb=24.0, cpu_cores=16
        )
        assert hw.can_run_light is True
        assert hw.can_run_medium is True
        assert hw.can_run_heavy is True
        assert hw.max_local_tier == "heavy"

    def test_32gb_no_gpu(self):
        hw = HardwareProfile(os_name="Linux", ram_total_gb=32.0, cpu_cores=16)
        assert hw.can_run_medium is True
        assert hw.can_run_heavy is False  # besoin GPU
        assert hw.max_local_tier == "medium"

    def test_2gb_ram(self):
        hw = HardwareProfile(os_name="Windows", ram_total_gb=2.0, cpu_cores=2)
        assert hw.can_run_light is False
        assert hw.max_local_tier is None

    def test_has_gpu(self):
        assert HardwareProfile(os_name="Win", ram_total_gb=8).has_gpu is False
        assert HardwareProfile(os_name="Win", ram_total_gb=8, gpu_name="RTX 3060").has_gpu is True

    def test_apple_silicon(self):
        with patch("platform.processor", return_value="arm"):
            hw = HardwareProfile(os_name="Darwin", ram_total_gb=16, cpu_name="Apple M1")
            assert hw.is_apple_silicon is True

    def test_not_apple_silicon(self):
        hw = HardwareProfile(os_name="Windows", ram_total_gb=16, cpu_name="Intel64")
        assert hw.is_apple_silicon is False


# ═══════════════════════════════════════════════════════════════════
# ModelCatalog
# ═══════════════════════════════════════════════════════════════════

class TestModelCatalog:
    def test_catalog_not_empty(self):
        assert len(MODEL_CATALOG) > 20

    def test_get_by_tier_light(self):
        light = get_catalog_by_tier(ModelTier.LIGHT)
        assert len(light) >= 3
        for entry in light:
            assert entry.tier == ModelTier.LIGHT

    def test_get_by_tier_medium(self):
        medium = get_catalog_by_tier(ModelTier.MEDIUM)
        assert len(medium) >= 8  # inclut abliterated + standard

    def test_get_by_tier_heavy(self):
        heavy = get_catalog_by_tier(ModelTier.HEAVY)
        assert len(heavy) >= 5  # inclut cloud

    def test_abliterated_models(self):
        ab = get_abliterated_models()
        assert len(ab) >= 4
        for entry in ab:
            assert entry.is_uncensored

    def test_recommended_per_tier(self):
        for tier in [ModelTier.LIGHT, ModelTier.MEDIUM, ModelTier.HEAVY]:
            recs = get_recommended(tier)
            assert len(recs) >= 1, f"No recommended for {tier.value}"

    def test_match_ollama_exact(self):
        entry = match_ollama_model("huihui_ai/llama3.1-abliterated:8b")
        assert entry is not None
        assert entry.is_abliterated

    def test_match_ollama_standard(self):
        entry = match_ollama_model("llama3.1:8b")
        assert entry is not None
        assert entry.tier == ModelTier.MEDIUM

    def test_match_ollama_unknown(self):
        entry = match_ollama_model("some-random-model:7b")
        assert entry is None

    def test_find_best_uncensored(self):
        available = [
            "huihui_ai/llama3.1-abliterated:8b",
            "llama3.1:8b",
            "mistral:7b",
        ]
        best = find_best_for_task(ModelTier.MEDIUM, prefer_uncensored=True,
                                   available_models=available)
        assert best is not None
        assert best.is_abliterated
        assert "abliterated" in best.name

    def test_find_best_standard(self):
        available = ["llama3.1:8b", "mistral:7b"]
        best = find_best_for_task(ModelTier.MEDIUM, prefer_uncensored=False,
                                   available_models=available)
        assert best is not None
        assert not best.is_abliterated  # le standard est prioritaire si pas de pref uncensored

    def test_catalog_entry_tags(self):
        ab_entry = get_abliterated_models()[0]
        assert ModelTag.ABLITERATED in ab_entry.tags
        assert ab_entry.is_uncensored is True


# ═══════════════════════════════════════════════════════════════════
# ModelSelector
# ═══════════════════════════════════════════════════════════════════

class TestModelSelector:
    @pytest.fixture
    def hw_medium(self):
        return HardwareProfile(os_name="Windows", ram_total_gb=16.0, cpu_cores=8)

    @pytest.fixture
    def hw_light(self):
        return HardwareProfile(os_name="Linux", ram_total_gb=4.0, cpu_cores=2)

    @pytest.mark.asyncio
    async def test_scan_empty(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[], healthy=True),
        }
        report = await selector.scan(providers)
        assert len(report.available_models) == 0

    @pytest.mark.asyncio
    async def test_scan_with_models(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
                make_model("llama3.2:3b", ProviderType.OLLAMA, ModelTier.LIGHT),
            ]),
        }
        report = await selector.scan(providers)
        assert len(report.available_models) == 2
        assert report.best_per_tier[ModelTier.MEDIUM] is not None
        assert report.best_per_tier[ModelTier.LIGHT] is not None
        assert report.best_per_tier[ModelTier.HEAVY] is None

    @pytest.mark.asyncio
    async def test_scan_abliterated_preferred(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium, prefer_uncensored=True)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
                make_model("huihui_ai/llama3.1-abliterated:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        report = await selector.scan(providers)
        best = report.best_per_tier[ModelTier.MEDIUM]
        assert best is not None
        assert best.is_uncensored
        assert "abliterated" in best.model

    @pytest.mark.asyncio
    async def test_select_prefer_uncensored(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium, prefer_uncensored=True)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
                make_model("huihui_ai/llama3.1-abliterated:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        await selector.scan(providers)
        result = await selector.select(ModelTier.MEDIUM, prefer_uncensored=True)
        assert result.is_uncensored
        assert "abliterated" in result.model

    @pytest.mark.asyncio
    async def test_select_no_uncensored_fallback(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        await selector.scan(providers)
        result = await selector.select(ModelTier.MEDIUM)
        assert result is not None
        assert result.tier == ModelTier.MEDIUM

    @pytest.mark.asyncio
    async def test_select_heavy_fallback_to_medium(self, hw_medium):
        """Si pas de HEAVY, fallback vers MEDIUM."""
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        await selector.scan(providers)
        # Devrait fallback de HEAVY → MEDIUM
        result = await selector.select(ModelTier.HEAVY)
        assert result.tier == ModelTier.MEDIUM  # fallback

    @pytest.mark.asyncio
    async def test_select_no_model_available(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[], healthy=True),
        }
        await selector.scan(providers)
        with pytest.raises(RuntimeError):
            await selector.select(ModelTier.MEDIUM)

    @pytest.mark.asyncio
    async def test_select_force_model(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
                make_model("mistral:7b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        await selector.scan(providers)
        result = await selector.select(ModelTier.MEDIUM, model="mistral:7b")
        assert result.model == "mistral:7b"

    @pytest.mark.asyncio
    async def test_airgap_blocks_cloud(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium, airgap=True)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
            ProviderType.OPENAI: MockProvider(models=[
                make_model("gpt-4o", ProviderType.OPENAI, ModelTier.HEAVY),
            ]),
        }
        await selector.scan(providers)
        result = await selector.select(ModelTier.HEAVY)
        # Devrait fallback car airgap bloque OpenAI
        assert result.tier == ModelTier.MEDIUM
        assert result.is_local is True

    @pytest.mark.asyncio
    async def test_recommendations_when_no_abliterated(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium, prefer_uncensored=True)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        report = await selector.scan(providers)
        assert len(report.recommendations) > 0
        assert any("abliterated" in r.lower() for r in report.recommendations)

    @pytest.mark.asyncio
    async def test_get_status(self, hw_medium):
        selector = ModelSelector(hardware=hw_medium)
        providers = {
            ProviderType.OLLAMA: MockProvider(models=[
                make_model("llama3.1:8b", ProviderType.OLLAMA, ModelTier.MEDIUM),
            ]),
        }
        await selector.scan(providers)
        status = selector.get_status()
        assert status["models_available"] == 1
        assert "medium" in status["by_tier"]
        assert len(status["by_tier"]["medium"]) == 1


# ═══════════════════════════════════════════════════════════════════
# BaseProvider Protocol
# ═══════════════════════════════════════════════════════════════════

class TestBaseProvider:
    def test_protocol_can_be_implemented(self):
        p = MockProvider()
        assert p.provider_type == ProviderType.OLLAMA
        assert isinstance(p, BaseProvider)

    def test_count_tokens_default(self):
        p = MockProvider()
        assert p.count_tokens("Hello world") > 0

    @pytest.mark.asyncio
    async def test_generate_returns_result(self):
        p = MockProvider()
        result = await p.generate(GenerateParams(prompt="test"))
        assert isinstance(result, GenerateResult)
        assert "mock" in result.text

    @pytest.mark.asyncio
    async def test_stream_yields_chunks(self):
        p = MockProvider()
        chunks = []
        async for chunk in p.stream(GenerateParams(prompt="test")):
            chunks.append(chunk)
        assert len(chunks) > 0
        assert "mock" in "".join(chunks)

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with MockProvider() as p:
            assert await p.health_check()


# ═══════════════════════════════════════════════════════════════════
# SelectionResult
# ═══════════════════════════════════════════════════════════════════

class TestSelectionResult:
    def test_display_name_local_uncensored(self):
        entry = get_abliterated_models()[0]
        result = SelectionResult(
            entry=entry, model="test:8b",
            provider=ProviderType.OLLAMA, tier=ModelTier.MEDIUM,
            is_uncensored=True, is_local=True, ram_required_gb=6.0,
            reason="test",
        )
        assert "🔓" in result.display_name
        assert "🏠" in result.display_name
        assert "☁️" not in result.display_name

    def test_display_name_cloud(self):
        result = SelectionResult(
            entry=None, model="gpt-4o",
            provider=ProviderType.OPENAI, tier=ModelTier.HEAVY,
            is_uncensored=False, is_local=False, ram_required_gb=0,
            reason="cloud",
        )
        assert "☁️" in result.display_name
        assert "🔓" not in result.display_name
