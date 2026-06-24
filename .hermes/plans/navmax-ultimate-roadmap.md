# NavMAX Ultimate — Roadmap v0.3.0 → v1.0.0

> **For Hermes:** Use plan + subagent-driven-development skills. Implement phase by phase, each phase validated before next.

**Goal:** Transformer NavMAX d'une boîte à outils pilotable par IA en **l'IA elle-même** — un agent autonome de cybersécurité offensif capable de recevoir un objectif en langage naturel et d'exécuter toute la chaîne reconnaissance→exploitation→reporting sans intervention humaine.

**Architecture:** 4 phases empilées verticalement. Chaque phase débloque la suivante. **Le moteur IA est un système multi-provider à 3 tiers** (Light ≤3B / Medium 7-8B / Heavy 70B+) avec auto-sélection selon le hardware et la tâche — un petit PC fait tourner les modèles Light, une machine avec GPU peut tout faire en local, et le cloud est disponible en fallback optionnel.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy async, Typer CLI, structlog, NetworkX, Ollama / llama.cpp / LM Studio (local LLM tiers), OpenAI/Anthropic/DeepSeek API (cloud fallback), Docker (sandbox), PromptFoo (red-teaming IA), MCP (connecteurs Anthropic).

---

## Dépendances inter-phases

```
P3 (Cerveau) ──────► P4 (Perception) ──────► P5 (Action) ──────► P6 (Orchestration)
IA locale          Scanner intelligent      Exploit génératif     One-Click Mission
Audit Trail        OSINT augmenté           Pivot automatique     Rapports IA
Fondation           Yeux de NavMAX          Poings de NavMAX      Interface ultime
```

---

# Phase 3 — Le Cerveau : IA Multi-Provider + Tiered + Audit Trail (3-4 semaines)

> **Pourquoi en premier :** Sans l'IA, les fonctionnalités P4-P6 sont impossibles (Mission Planner, Semantic Search, AI Exploit Generator). L'Audit Trail est nécessaire pour que TOUTES les actions ultérieures soient traçables.

## Architecture du moteur IA

```
┌──────────────────────────────────────────────────────────────────┐
│                        NAVMAX AI ENGINE                           │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ TIER 1       │  │ TIER 2       │  │ TIER 3       │           │
│  │ Light (≤3B)  │  │ Medium (7-8B)│  │ Heavy (≥70B) │           │
│  │              │  │              │  │              │           │
│  │ • Extraction │  │ • Planning   │  │ • Exploit gen│           │
│  │ • Classifier │  │ • Analysis   │  │ • Code gen   │           │
│  │ • Validation │  │ • Summarize  │  │ • Reasoning  │           │
│  │ • Routing    │  │ • Translate  │  │ • Debug      │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
│         │                 │                 │                     │
│  ┌──────┴─────────────────┴─────────────────┴───────────────┐    │
│  │                   PROVIDER ABSTRACTION                     │    │
│  │                                                            │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │    │
│  │  │ Ollama   │ │llama.cpp │ │LM Studio │ │ OpenAI/      │ │    │
│  │  │ (local)  │ │ (local)  │ │ (local)  │ │ Anthropic    │ │    │
│  │  │ HTTP API │ │ GGUF raw │ │ REST API │ │ DeepSeek API │ │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘ │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │              HARDWARE DETECTION & AUTO-CONFIG               │   │
│  │  RAM: 8GB → light only │ 16GB → light+medium │ 32GB+ → all│   │
│  │  GPU: none → CPU/GGUF │ CUDA → llama.cpp │ Apple → MLX    │   │
│  └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### Tiers de modèles — quel modèle pour quelle tâche

| Tier | Paramètres | RAM min | Tâches | Modèles recommandés (Q4_K_M) |
|---|---|---|---|---|
| **Light** | 1-3B | 2-4 GB | Classification, extraction d'infos, validation JSON, routage, parsing de bannières | `llama3.2:3b`, `qwen2.5:3b`, `phi3:3.8b` |
| **Medium** | 7-8B | 6-8 GB | Planification de mission, analyse de scans, résumé OSINT, traduction NL→Cypher, choix d'exploit | `llama3.1:8b`, `mistral:7b`, `qwen2.5:7b` |
| **Heavy** | 70B+ | 40+ GB | Génération d'exploit, debug de code complexe, raisonnement multi-étapes, audit de sécurité | `llama3.1:70b`, `codellama:70b`, `deepseek-coder-v2` |

### Providers supportés

| Provider | Type | Setup | Idéal pour |
|---|---|---|---|
| **Ollama** | Local HTTP | `winget install Ollama.Ollama` | Tout le monde — le plus simple |
| **llama.cpp** | Local raw GGUF | `.gguf` files + Python bindings | Performance max, GPU NVIDIA |
| **LM Studio** | Local REST | Interface graphique Windows | Utilisateurs non techniques |
| **OpenAI API** | Cloud | `$OPENAI_API_KEY` | Fallback rapide, modèles puissants |
| **Anthropic API** | Cloud | `$ANTHROPIC_API_KEY` | Meilleur raisonnement |
| **DeepSeek API** | Cloud | `$DEEPSEEK_API_KEY` | Moins cher, bon pour le code |

### Règle de sélection automatique

```
SI mode_airgap = true → providers cloud désactivés
SI RAM < 8GB → TIER_LIGHT uniquement, tout le reste → cloud (si disponible)
SI RAM 8-16GB → TIER_LIGHT + TIER_MEDIUM locaux, TIER_HEAVY → cloud
SI RAM ≥ 32GB → tout en local possible (TIER_HEAVY=Q2_K pour 24GB, Q4_K_M pour 40GB+)
SI GPU détecté → llama.cpp prioritaire sur Ollama (perf 2-3x)
```

---

## P3.1 — Providers & Hardware Detection (Fondation)

### Task 3.1.0: Module `navmax/ai/providers/` — Interface abstraite

**Objective:** Définir le protocol `BaseProvider` que tous les backends implémentent.

**Files:**
- Create: `navmax/ai/__init__.py`
- Create: `navmax/ai/providers/__init__.py`
- Create: `navmax/ai/providers/base.py`
- Create: `tests/test_ai_providers.py`

**Code — Protocol abstrait :**

```python
# navmax/ai/providers/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional
from enum import Enum

class ModelTier(str, Enum):
    LIGHT = "light"    # 1-3B — classification, extraction, routing
    MEDIUM = "medium"  # 7-8B — planning, analysis, summarization
    HEAVY = "heavy"    # 70B+ — code generation, complex reasoning

class ProviderType(str, Enum):
    OLLAMA = "ollama"
    LLAMACPP = "llamacpp"
    LMSTUDIO = "lmstudio"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"

@dataclass
class ModelInfo:
    name: str                          # "llama3.1:8b", "gpt-4o"
    provider: ProviderType
    tier: ModelTier
    context_window: int = 8192
    supports_streaming: bool = True
    supports_tools: bool = False

@dataclass
class GenerateParams:
    prompt: str
    system: Optional[str] = None
    max_tokens: int = 2048
    temperature: float = 0.7
    stop_sequences: list[str] = field(default_factory=list)
    json_mode: bool = False  # force JSON output

@dataclass  
class GenerateResult:
    text: str
    model: str
    provider: ProviderType
    tokens_used: int
    tokens_per_second: float
    finish_reason: str  # "stop", "length", "error"

class BaseProvider(ABC):
    """Abstract interface for all LLM backends."""

    provider_type: ProviderType

    @abstractmethod
    async def generate(self, params: GenerateParams) -> GenerateResult:
        """Single-turn generation."""

    @abstractmethod
    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        """Streaming generation, yields text chunks."""

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Return models available through this provider."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if provider is reachable."""

    @abstractmethod
    def count_tokens(self, text: str, model: str) -> int:
        """Accurate token count for the given model."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass
```

**Step 1: Test de l'interface** → vérifie que le protocol est utilisable.

```python
# tests/test_ai_providers.py
import pytest
from navmax.ai.providers.base import BaseProvider, ModelTier, ProviderType, ModelInfo, GenerateParams, GenerateResult

class MockProvider(BaseProvider):
    provider_type = ProviderType.OLLAMA

    async def generate(self, params: GenerateParams) -> GenerateResult:
        return GenerateResult(
            text="mock response", model="mock:1b",
            provider=self.provider_type, tokens_used=3,
            tokens_per_second=10.0, finish_reason="stop"
        )

    async def stream(self, params: GenerateParams):
        yield "mock "
        yield "response"

    async def list_models(self):
        return [ModelInfo(name="mock:1b", provider=ProviderType.OLLAMA, tier=ModelTier.LIGHT)]

    async def health_check(self):
        return True

    def count_tokens(self, text, model):
        return len(text.split())

@pytest.mark.asyncio
async def test_provider_protocol():
    p = MockProvider()
    assert await p.health_check()
    result = await p.generate(GenerateParams(prompt="test"))
    assert result.text == "mock response"
    models = await p.list_models()
    assert len(models) == 1
    assert models[0].tier == ModelTier.LIGHT
```

**Commit**

```bash
git add navmax/ai/ tests/test_ai_providers.py
git commit -m "feat(ai): define BaseProvider protocol + ModelTier enum"
```

---

### Task 3.1.1: Hardware Detection

**Objective:** Détecter RAM, GPU, CPU pour auto-configurer les tiers disponibles.

**Files:**
- Create: `navmax/ai/hardware.py`
- Create: `tests/test_hardware.py`

```python
# navmax/ai/hardware.py
import os
import platform
import subprocess
from dataclasses import dataclass, field

@dataclass
class HardwareProfile:
    os_name: str
    ram_total_gb: float
    gpu_name: Optional[str] = None
    gpu_vram_gb: Optional[float] = None
    cpu_cores: int = 4
    cpu_name: str = ""

    @property
    def can_run_light(self) -> bool:
        return self.ram_total_gb >= 4

    @property
    def can_run_medium(self) -> bool:
        return self.ram_total_gb >= 8

    @property
    def can_run_heavy(self) -> bool:
        return self.ram_total_gb >= 32 and self.gpu_vram_gb and self.gpu_vram_gb >= 16

    @property
    def max_local_tier(self):
        if self.can_run_heavy:
            return "heavy"
        elif self.can_run_medium:
            return "medium"
        elif self.can_run_light:
            return "light"
        return None


def detect_hardware() -> HardwareProfile:
    """Auto-detect system resources. Cross-platform (Windows, macOS, Linux)."""
    system = platform.system()
    ram = _detect_ram(system)
    gpu_name, gpu_vram = _detect_gpu(system)
    cpu_cores = os.cpu_count() or 4
    cpu_name = platform.processor() or ""

    return HardwareProfile(
        os_name=system,
        ram_total_gb=ram,
        gpu_name=gpu_name,
        gpu_vram_gb=gpu_vram,
        cpu_cores=cpu_cores,
        cpu_name=cpu_name,
    )

def _detect_ram(system: str) -> float:
    if system == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            mem = MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
            return round(mem.ullTotalPhys / (1024**3), 1)
        except Exception:
            return 8.0  # fallback
    elif system == "Linux":
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if "MemTotal" in line:
                        kb = int(line.split()[1])
                        return round(kb / (1024**2), 1)
        except Exception:
            pass
    elif system == "Darwin":
        try:
            result = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True)
            return round(int(result.stdout.strip()) / (1024**3), 1)
        except Exception:
            pass
    return 8.0

def _detect_gpu(system: str) -> tuple[Optional[str], Optional[float]]:
    """Detect GPU name and VRAM. Returns (name, vram_gb)."""
    try:
        # Try nvidia-smi (Windows + Linux)
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(",")
            if len(parts) == 2:
                name = parts[0].strip()
                vram_mb = int(parts[1].strip().replace(" MiB", ""))
                return name, round(vram_mb / 1024, 1)
    except Exception:
        pass

    # Apple Silicon — no discrete GPU but unified memory
    if system == "Darwin" and platform.processor() == "arm":
        return "Apple Silicon (Unified)", None

    return None, None
```

**Tests unitaires** (mockables, pas besoin de vrai GPU) :

```python
# tests/test_hardware.py
from navmax.ai.hardware import detect_hardware, HardwareProfile

def test_detect_does_not_crash():
    hw = detect_hardware()
    assert hw.ram_total_gb > 0
    assert hw.cpu_cores > 0

def test_tier_logic_8gb_ram():
    hw = HardwareProfile(os_name="Windows", ram_total_gb=8.0, cpu_cores=4)
    assert hw.can_run_light is True
    assert hw.can_run_medium is True
    assert hw.can_run_heavy is False
    assert hw.max_local_tier == "medium"

def test_tier_logic_32gb_ram_with_gpu():
    hw = HardwareProfile(os_name="Windows", ram_total_gb=32.0, gpu_name="RTX 4090", gpu_vram_gb=24.0, cpu_cores=16)
    assert hw.can_run_light is True
    assert hw.can_run_medium is True
    assert hw.can_run_heavy is True
    assert hw.max_local_tier == "heavy"

def test_tier_logic_4gb_ram():
    hw = HardwareProfile(os_name="Linux", ram_total_gb=4.0, cpu_cores=2)
    assert hw.can_run_light is True
    assert hw.can_run_medium is False
    assert hw.max_local_tier == "light"

def test_tier_logic_2gb_ram():
    hw = HardwareProfile(os_name="Windows", ram_total_gb=2.0, cpu_cores=2)
    assert hw.can_run_light is False
    assert hw.max_local_tier is None
```

**Commit**

```bash
git add navmax/ai/hardware.py tests/test_hardware.py
git commit -m "feat(ai): add hardware detection (RAM, GPU, CPU) and tier logic"
```

---

### Task 3.1.2: Ollama Provider

**Objective:** Implémenter `BaseProvider` pour Ollama (le provider local par défaut — le plus simple à installer).

**Files:**
- Create: `navmax/ai/providers/ollama.py`

```python
# navmax/ai/providers/ollama.py
import json
import time
import aiohttp
from typing import AsyncIterator
import structlog
from navmax.ai.providers.base import (
    BaseProvider, ProviderType, ModelTier, ModelInfo,
    GenerateParams, GenerateResult
)

logger = structlog.get_logger(__name__)

# Known Ollama models → tier mapping
OLLAMA_TIER_MAP = {
    "llama3.2:3b": ModelTier.LIGHT,
    "qwen2.5:3b": ModelTier.LIGHT,
    "phi3:3.8b": ModelTier.LIGHT,
    "phi3:mini": ModelTier.LIGHT,
    "gemma2:2b": ModelTier.LIGHT,
    "llama3.1:8b": ModelTier.MEDIUM,
    "mistral:7b": ModelTier.MEDIUM,
    "qwen2.5:7b": ModelTier.MEDIUM,
    "gemma2:9b": ModelTier.MEDIUM,
    "deepseek-r1:8b": ModelTier.MEDIUM,
    "codellama:7b": ModelTier.MEDIUM,
    "llama3.1:70b": ModelTier.HEAVY,
    "codellama:70b": ModelTier.HEAVY,
    "deepseek-r1:70b": ModelTier.HEAVY,
    "qwen2.5:72b": ModelTier.HEAVY,
}

class OllamaProvider(BaseProvider):
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
                        name=name, provider=ProviderType.OLLAMA, tier=tier,
                        context_window=8192, supports_streaming=True
                    ))
                self._model_cache = models
                return models

    def _guess_tier(self, model_name: str) -> ModelTier:
        # Exact match first
        if model_name in OLLAMA_TIER_MAP:
            return OLLAMA_TIER_MAP[model_name]
        # Heuristic: tag with :latest might be an alias — check base name
        base = model_name.split(":")[0]
        for known, tier in OLLAMA_TIER_MAP.items():
            if known.startswith(base):
                return tier
        # Fallback: size hints in name
        name_lower = model_name.lower()
        if any(s in name_lower for s in ["3b", "1b", "mini", "tiny", "small"]):
            return ModelTier.LIGHT
        if any(s in name_lower for s in ["7b", "8b", "9b", "13b"]):
            return ModelTier.MEDIUM
        if any(s in name_lower for s in ["70b", "72b", "405b"]):
            return ModelTier.HEAVY
        return ModelTier.MEDIUM  # safest default

    async def generate(self, params: GenerateParams) -> GenerateResult:
        t0 = time.monotonic()
        payload = {
            "model": params.model or "llama3.1:8b",
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
                json=payload, timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                elapsed = time.monotonic() - t0
                return GenerateResult(
                    text=data.get("response", ""),
                    model=payload["model"],
                    provider=ProviderType.OLLAMA,
                    tokens_used=data.get("eval_count", 0),
                    tokens_per_second=data.get("eval_count", 0) / max(elapsed, 0.01),
                    finish_reason="stop" if data.get("done") else "length"
                )

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        payload = {
            "model": params.model or "llama3.1:8b",
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
                json=payload, timeout=aiohttp.ClientTimeout(total=self.timeout)
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

    def count_tokens(self, text: str, model: str = "") -> int:
        # Ollama doesn't expose tokenizer API → heuristic
        # ~3.5 chars/token for code, ~4 for natural language
        return max(1, len(text) // 4)
```

**Tests (mock Ollama HTTP) → Commit**

---

### Task 3.1.3: OpenAI-compatible Provider (Cloud)

**Objective:** Provider pour OpenAI, Anthropic, DeepSeek — tous utilisent une API compatible OpenAI.

**Files:**
- Create: `navmax/ai/providers/openai_compat.py`

```python
# navmax/ai/providers/openai_compat.py
"""Provider for OpenAI-compatible APIs: OpenAI, Anthropic (via proxy), DeepSeek, etc."""
import time
import aiohttp
from typing import AsyncIterator, Optional
import structlog
from navmax.ai.providers.base import (
    BaseProvider, ProviderType, ModelTier, ModelInfo,
    GenerateParams, GenerateResult
)

logger = structlog.get_logger(__name__)

class OpenAICompatProvider(BaseProvider):
    """Generic provider for any OpenAI-compatible chat completions API."""

    def __init__(self, provider_type: ProviderType, base_url: str,
                 api_key: str, timeout: int = 120):
        self.provider_type = provider_type
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def health_check(self) -> bool:
        try:
            async with aiohttp.ClientSession() as s:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                async with s.get(f"{self.base_url}/models", headers=headers, timeout=10) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def list_models(self) -> list[ModelInfo]:
        async with aiohttp.ClientSession() as s:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            async with s.get(f"{self.base_url}/models", headers=headers, timeout=10) as resp:
                data = await resp.json()
                return [
                    ModelInfo(
                        name=m["id"], provider=self.provider_type,
                        tier=self._guess_tier(m["id"]),
                        context_window=8192, supports_streaming=True, supports_tools=True
                    )
                    for m in data.get("data", [])
                ]

    def _guess_tier(self, model_name: str) -> ModelTier:
        n = model_name.lower()
        if any(s in n for s in ["gpt-4o", "claude-3-opus", "claude-3.5", "deepseek-v4"]):
            return ModelTier.HEAVY
        if any(s in n for s in ["gpt-4", "claude-3-sonnet", "deepseek-v3"]):
            return ModelTier.HEAVY
        if any(s in n for s in ["gpt-3.5", "claude-3-haiku", "deepseek-chat"]):
            return ModelTier.MEDIUM
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
            "Content-Type": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/chat/completions",
                json=payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                elapsed = time.monotonic() - t0
                choice = data["choices"][0]
                return GenerateResult(
                    text=choice["message"]["content"],
                    model=model, provider=self.provider_type,
                    tokens_used=data.get("usage", {}).get("total_tokens", 0),
                    tokens_per_second=data.get("usage", {}).get("total_tokens", 0) / max(elapsed, 0.01),
                    finish_reason=choice.get("finish_reason", "stop")
                )

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        model = params.model or "gpt-4o-mini"
        messages = []
        if params.system:
            messages.append({"role": "system", "content": params.system})
        messages.append({"role": "user", "content": params.prompt})

        payload = {
            "model": model, "messages": messages,
            "max_tokens": params.max_tokens, "temperature": params.temperature,
            "stream": True
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/chat/completions",
                json=payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                resp.raise_for_status()
                async for line in resp.content:
                    line = line.decode().strip()
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            chunk = json.loads(line[6:])
                            delta = chunk["choices"][0].get("delta", {})
                            if "content" in delta:
                                yield delta["content"]
                        except (json.JSONDecodeError, KeyError, IndexError):
                            continue

    def count_tokens(self, text: str, model: str = "") -> int:
        # Generic: ~4 chars per token
        return max(1, len(text) // 4)
```

**Tests → Commit**

---

### Task 3.1.4: LlamaCpp Provider (local raw GGUF — performance max)

**Objective:** Provider direct llama.cpp pour les utilisateurs avancés avec GPU NVIDIA.

**Files:**
- Create: `navmax/ai/providers/llamacpp.py`

```python
# navmax/ai/providers/llamacpp.py
"""llama.cpp provider — direct GGUF inference with GPU acceleration.
Requires: pip install llama-cpp-python
Optional CUDA: CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python
"""
import time
from pathlib import Path
from typing import AsyncIterator, Optional
import structlog
from navmax.ai.providers.base import (
    BaseProvider, ProviderType, ModelTier, ModelInfo,
    GenerateParams, GenerateResult
)

logger = structlog.get_logger(__name__)

class LlamaCppProvider(BaseProvider):
    provider_type = ProviderType.LLAMACPP

    def __init__(self, model_path: str | Path, n_ctx: int = 8192,
                 n_gpu_layers: int = -1,  # -1 = auto, 0 = CPU only
                 n_threads: Optional[int] = None,
                 verbose: bool = False):
        self.model_path = Path(model_path)
        self._model = None
        self._n_ctx = n_ctx
        self._n_gpu_layers = n_gpu_layers
        self._n_threads = n_threads
        self._verbose = verbose

    def _load_model(self):
        if self._model is not None:
            return
        from llama_cpp import Llama
        self._model = Llama(
            model_path=str(self.model_path),
            n_ctx=self._n_ctx,
            n_gpu_layers=self._n_gpu_layers,
            n_threads=self._n_threads,
            verbose=self._verbose,
        )

    async def health_check(self) -> bool:
        return self.model_path.exists()

    async def list_models(self) -> list[ModelInfo]:
        if not self.model_path.exists():
            return []
        name = self.model_path.stem
        tier = self._guess_tier_from_filename(name)
        return [ModelInfo(
            name=name, provider=ProviderType.LLAMACPP, tier=tier,
            context_window=self._n_ctx, supports_streaming=True
        )]

    def _guess_tier_from_filename(self, name: str) -> ModelTier:
        n = name.lower()
        if any(s in n for s in ["70b", "72b", "405b"]):
            return ModelTier.HEAVY
        if any(s in n for s in ["7b", "8b", "9b", "13b"]):
            return ModelTier.MEDIUM
        if any(s in n for s in ["1b", "3b", "mini"]):
            return ModelTier.LIGHT
        return ModelTier.MEDIUM

    async def generate(self, params: GenerateParams) -> GenerateResult:
        t0 = time.monotonic()
        self._load_model()

        prompt = params.prompt
        if params.system:
            # llama.cpp uses chat format for system prompts
            prompt = f"<|system|>\n{params.system}</s>\n<|user|>\n{params.prompt}</s>\n<|assistant|>\n"

        result = self._model(
            prompt,
            max_tokens=params.max_tokens,
            temperature=params.temperature,
            stop=params.stop_sequences or None,
            echo=False,
        )
        elapsed = time.monotonic() - t0
        text = result["choices"][0]["text"]
        return GenerateResult(
            text=text,
            model=self.model_path.stem,
            provider=ProviderType.LLAMACPP,
            tokens_used=result.get("usage", {}).get("total_tokens", 0),
            tokens_per_second=result.get("usage", {}).get("total_tokens", 0) / max(elapsed, 0.01),
            finish_reason=result["choices"][0].get("finish_reason", "stop")
        )

    async def stream(self, params: GenerateParams) -> AsyncIterator[str]:
        self._load_model()

        prompt = params.prompt
        if params.system:
            prompt = f"<|system|>\n{params.system}</s>\n<|user|>\n{params.prompt}</s>\n<|assistant|>\n"

        for chunk in self._model(
            prompt, max_tokens=params.max_tokens,
            temperature=params.temperature, stream=True, echo=False
        ):
            text = chunk["choices"][0].get("text", "")
            if text:
                yield text

    def count_tokens(self, text: str, model: str = "") -> int:
        self._load_model()
        return len(self._model.tokenize(text.encode()))
```

**Tests → Commit**

---

### Task 3.1.5: LM Studio Provider (REST — pour utilisateurs GUI Windows)

**Files:**
- Create: `navmax/ai/providers/lmstudio.py`

LM Studio expose une API compatible OpenAI sur `http://localhost:1234`. On hérite de `OpenAICompatProvider` :

```python
# navmax/ai/providers/lmstudio.py
from navmax.ai.providers.base import ProviderType
from navmax.ai.providers.openai_compat import OpenAICompatProvider

class LMStudioProvider(OpenAICompatProvider):
    def __init__(self, base_url: str = "http://localhost:1234", timeout: int = 120):
        super().__init__(
            provider_type=ProviderType.LMSTUDIO,
            base_url=base_url,
            api_key="lm-studio",  # LM Studio doesn't require auth
            timeout=timeout,
        )
```

**Tests → Commit**

---

## P3.2 — AIEngine : l'orchestrateur multi-provider (le cœur)

### Task 3.2.0: `AIEngine` — sélection automatique provider × tier × tâche

**Files:**
- Create: `navmax/ai/engine.py`
- Create: `navmax/ai/config.py`
- Create: `tests/test_ai_engine.py`

```python
# navmax/ai/config.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from navmax.ai.providers.base import ModelTier, ProviderType

@dataclass
class ProviderConfig:
    """Config for a single provider."""
    provider_type: ProviderType
    enabled: bool = True
    priority: int = 1  # lower = tried first

    # Ollama / LM Studio
    base_url: str = "http://localhost:11434"

    # llama.cpp
    model_path: Optional[str] = None
    n_gpu_layers: int = -1  # -1 = auto

    # OpenAI / Anthropic / DeepSeek
    api_key: Optional[str] = None  # if None, read from env var
    api_key_env: str = ""  # e.g. "OPENAI_API_KEY"

    # Model tier overrides
    light_model: Optional[str] = None
    medium_model: Optional[str] = None
    heavy_model: Optional[str] = None


@dataclass
class AIEngineConfig:
    """Master config for the AI engine."""
    # Operating mode
    airgap: bool = False            # if True, disable ALL cloud providers
    prefer_local: bool = True       # if True, try local before cloud

    # Provider configs
    ollama: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        provider_type=ProviderType.OLLAMA, priority=1,
        light_model="llama3.2:3b", medium_model="llama3.1:8b", heavy_model="llama3.1:70b"
    ))
    llamacpp: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        provider_type=ProviderType.LLAMACPP, priority=1, enabled=False  # disabled by default
    ))
    lmstudio: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        provider_type=ProviderType.LMSTUDIO, priority=2,
        base_url="http://localhost:1234"
    ))
    openai: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        provider_type=ProviderType.OPENAI, priority=10,  # cloud = lower priority
        api_key_env="OPENAI_API_KEY"
    ))
    anthropic: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        provider_type=ProviderType.ANTHROPIC, priority=10,
        base_url="https://api.anthropic.com", api_key_env="ANTHROPIC_API_KEY"
    ))
    deepseek: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        provider_type=ProviderType.DEEPSEEK, priority=10,
        base_url="https://api.deepseek.com", api_key_env="DEEPSEEK_API_KEY"
    ))

    # Paths
    models_dir: str = "~/.navmax/models"

    # Limits
    max_local_tier: Optional[ModelTier] = None  # auto-detected if None
```

```python
# navmax/ai/engine.py
import os
import asyncio
from typing import AsyncIterator, Optional
import structlog
from pathlib import Path

from navmax.ai.providers.base import (
    BaseProvider, ModelTier, ProviderType,
    GenerateParams, GenerateResult
)
from navmax.ai.config import AIEngineConfig, ProviderConfig
from navmax.ai.hardware import detect_hardware

logger = structlog.get_logger(__name__)

# Singleton
_engine: Optional["AIEngine"] = None

def get_engine(config: Optional[AIEngineConfig] = None) -> "AIEngine":
    global _engine
    if _engine is None:
        _engine = AIEngine(config)
    return _engine


class AIEngine:
    """Multi-provider, tiered LLM engine with auto-selection."""

    def __init__(self, config: Optional[AIEngineConfig] = None):
        self.config = config or AIEngineConfig()
        self._providers: dict[ProviderType, BaseProvider] = {}
        self._hw = detect_hardware()
        self._initialized = False

        # Override max_local_tier from hardware if not set
        if self.config.max_local_tier is None:
            tier_map = {"light": ModelTier.LIGHT, "medium": ModelTier.MEDIUM, "heavy": ModelTier.HEAVY}
            self.config.max_local_tier = tier_map.get(self._hw.max_local_tier)

    async def initialize(self) -> dict:
        """Initialize all configured providers. Returns status report."""
        if self._initialized:
            return {"status": "already_initialized"}

        status = {"hardware": {"ram_gb": self._hw.ram_total_gb, "gpu": self._hw.gpu_name,
                                "max_local_tier": self._hw.max_local_tier},
                   "providers": {}}

        provider_configs = [
            ("ollama", self.config.ollama),
            ("llamacpp", self.config.llamacpp),
            ("lmstudio", self.config.lmstudio),
        ]
        # Cloud providers disabled in airgap mode
        if not self.config.airgap:
            provider_configs += [
                ("openai", self.config.openai),
                ("anthropic", self.config.anthropic),
                ("deepseek", self.config.deepseek),
            ]

        for name, pc in provider_configs:
            if not pc.enabled:
                continue
            provider = await self._init_provider(pc)
            if provider and await provider.health_check():
                self._providers[pc.provider_type] = provider
                models = await provider.list_models()
                status["providers"][name] = {
                    "status": "available",
                    "models": [m.name for m in models],
                    "tiers_available": list(set(m.tier.value for m in models))
                }
            else:
                status["providers"][name] = {"status": "unavailable"}

        self._initialized = True
        return status

    async def _init_provider(self, pc: ProviderConfig) -> Optional[BaseProvider]:
        """Instantiate a provider from its config."""
        try:
            if pc.provider_type == ProviderType.OLLAMA:
                from navmax.ai.providers.ollama import OllamaProvider
                return OllamaProvider(base_url=pc.base_url)
            elif pc.provider_type == ProviderType.LLAMACPP:
                if not pc.model_path:
                    return None
                from navmax.ai.providers.llamacpp import LlamaCppProvider
                return LlamaCppProvider(
                    model_path=os.path.expanduser(pc.model_path),
                    n_gpu_layers=pc.n_gpu_layers
                )
            elif pc.provider_type == ProviderType.LMSTUDIO:
                from navmax.ai.providers.lmstudio import LMStudioProvider
                return LMStudioProvider(base_url=pc.base_url)
            elif pc.provider_type in (ProviderType.OPENAI, ProviderType.ANTHROPIC, ProviderType.DEEPSEEK):
                api_key = pc.api_key or os.environ.get(pc.api_key_env, "")
                if not api_key:
                    logger.warning("no_api_key", provider=pc.provider_type.value)
                    return None
                from navmax.ai.providers.openai_compat import OpenAICompatProvider
                base = pc.base_url or self._default_base_url(pc.provider_type)
                return OpenAICompatProvider(
                    provider_type=pc.provider_type, base_url=base, api_key=api_key
                )
        except ImportError as e:
            logger.warning("provider_import_failed", provider=pc.provider_type.value, error=str(e))
            return None
        except Exception as e:
            logger.error("provider_init_failed", provider=pc.provider_type.value, error=str(e))
            return None

    async def generate(self, prompt: str, *, tier: ModelTier = ModelTier.MEDIUM,
                       system: Optional[str] = None, max_tokens: int = 2048,
                       temperature: float = 0.7, json_mode: bool = False,
                       provider: Optional[ProviderType] = None,
                       model: Optional[str] = None) -> GenerateResult:
        """Generate text. Auto-selects the best provider/model for the tier."""
        params = GenerateParams(
            prompt=prompt, system=system, max_tokens=max_tokens,
            temperature=temperature, json_mode=json_mode
        )
        if model:
            params.model = model

        provider, model_used = await self._select_provider(tier, provider, model)
        params.model = model_used
        return await provider.generate(params)

    async def stream(self, prompt: str, *, tier: ModelTier = ModelTier.MEDIUM,
                     system: Optional[str] = None, max_tokens: int = 2048,
                     temperature: float = 0.7,
                     provider: Optional[ProviderType] = None,
                     model: Optional[str] = None) -> AsyncIterator[str]:
        """Streaming generation."""
        params = GenerateParams(
            prompt=prompt, system=system, max_tokens=max_tokens,
            temperature=temperature
        )
        if model:
            params.model = model

        provider, model_used = await self._select_provider(tier, provider, model)
        params.model = model_used
        async for chunk in provider.stream(params):
            yield chunk

    async def _select_provider(self, tier: ModelTier, preferred_provider: Optional[ProviderType],
                                preferred_model: Optional[str]) -> tuple[BaseProvider, str]:
        """Select the best provider and model for the given tier.

        Rules:
        1. If preferred_provider is given, use it (health-check permitting)
        2. If airgap mode, only local providers
        3. For LIGHT/MEDIUM tiers: prefer local, fallback to cloud
        4. For HEAVY tier: try local if hardware permits, else cloud
        5. Within same priority, use first healthy provider
        """
        candidates = []

        for pt, prov in self._providers.items():
            pc = self._get_provider_config(pt)
            models = await prov.list_models()
            tier_models = [m for m in models if m.tier == tier]
            if not tier_models:
                continue
            candidates.append((pc.priority, prov, tier_models[0].name))

        if not candidates:
            # Try fallback to next tier down
            fallback_tier = {
                ModelTier.HEAVY: ModelTier.MEDIUM,
                ModelTier.MEDIUM: ModelTier.LIGHT,
            }.get(tier)
            if fallback_tier:
                logger.warning("tier_fallback", from_tier=tier.value, to_tier=fallback_tier.value)
                return await self._select_provider(fallback_tier, preferred_provider, preferred_model)
            raise RuntimeError(f"No provider available for tier {tier.value}")

        candidates.sort(key=lambda c: c[0])  # sort by priority
        if preferred_provider:
            for prio, prov, model in candidates:
                if prov.provider_type == preferred_provider:
                    return prov, model

        return candidates[0][1], candidates[0][2]

    def _get_provider_config(self, pt: ProviderType) -> ProviderConfig:
        mapping = {
            ProviderType.OLLAMA: self.config.ollama,
            ProviderType.LLAMACPP: self.config.llamacpp,
            ProviderType.LMSTUDIO: self.config.lmstudio,
            ProviderType.OPENAI: self.config.openai,
            ProviderType.ANTHROPIC: self.config.anthropic,
            ProviderType.DEEPSEEK: self.config.deepseek,
        }
        return mapping.get(pt, ProviderConfig(provider_type=pt))

    @staticmethod
    def _default_base_url(pt: ProviderType) -> str:
        return {
            ProviderType.OPENAI: "https://api.openai.com/v1",
            ProviderType.ANTHROPIC: "https://api.anthropic.com",
            ProviderType.DEEPSEEK: "https://api.deepseek.com",
        }.get(pt, "")
```

**Tests → Commit**

```bash
git add navmax/ai/engine.py navmax/ai/config.py tests/test_ai_engine.py
git commit -m "feat(ai): multi-provider AIEngine with auto tier selection"
```

---

### Task 3.2.1: API Routes (mise à jour)

**Objective:** Exposer l'engine multi-provider via REST avec endpoints de diagnostic.

**Files:**
- Create: `navmax/api/routes/ai.py`
- Modify: `navmax/api/routes/__init__.py`

Endpoints :
- `POST /api/v1/ai/generate` — génération (auto-sélection)
- `POST /api/v1/ai/stream` — streaming SSE
- `GET /api/v1/ai/status` — état des providers, hardware, modèles disponibles
- `GET /api/v1/ai/models` — liste tous les modèles de tous les providers
- `POST /api/v1/ai/reload` — réinitialise les providers (après changement de config)

**Tests → Commit**

---

## P3.3 — Planificateur de Mission Autonome

*(inchangé par rapport au plan original — le planner utilise maintenant `engine.generate(tier=ModelTier.MEDIUM)` au lieu d'un provider fixe)*

---

## P3.4 — Audit Trail (Fondation transverse)

*(inchangé)*

---

## P3.5 — Tableau de Bord Cognitif (Web)

*(inchangé)*

---

## P3.2 — Planificateur de Mission Autonome

**Objectif:** Un agent LLM qui reçoit un objectif en langage naturel et décompose en sous-tâches exécutables.

### Task 3.2.1: Mission Planner core

**Files:**
- Create: `navmax/ai/mission_planner.py`
- Create: `tests/test_mission_planner.py`

```python
# navmax/ai/mission_planner.py
import json
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import structlog
from navmax.ai.engine import AIEngine
from navmax.ai.prompts import MISSION_PLANNER_SYSTEM, MISSION_PLANNER_TEMPLATE
from jinja2 import Template

logger = structlog.get_logger(__name__)

class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class MissionPhase:
    id: str
    description: str
    module_needed: str  # scanner, osint, exploit, proxy, sandbox
    parameters: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    status: PhaseStatus = PhaseStatus.PENDING
    result: Optional[dict] = None
    error: Optional[str] = None

@dataclass
class MissionPlan:
    objective: str
    target: Optional[str] = None
    phases: list[MissionPhase] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

class MissionPlanner:
    def __init__(self, engine: AIEngine):
        self.engine = engine

    async def plan(self, objective: str, target: Optional[str] = None,
                   scope: Optional[str] = None, constraints: Optional[str] = None) -> MissionPlan:
        template = Template(MISSION_PLANNER_TEMPLATE)
        prompt = template.render(
            objective=objective, target=target,
            scope=scope, constraints=constraints
        )

        response = await self.engine.generate(
            prompt, system=MISSION_PLANNER_SYSTEM,
            temperature=0.3, max_tokens=4096
        )

        return self._parse_plan(response, objective, target)

    def _parse_plan(self, response: str, objective: str, target: Optional[str]) -> MissionPlan:
        # Extract JSON from response (may be wrapped in markdown)
        try:
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0]
            else:
                json_str = response

            data = json.loads(json_str)
            phases = [
                MissionPhase(
                    id=p.get("id", f"phase_{i}"),
                    description=p["description"],
                    module_needed=p["module_needed"],
                    parameters=p.get("parameters", {}),
                    depends_on=p.get("depends_on", [])
                )
                for i, p in enumerate(data.get("phases", []))
            ]
            return MissionPlan(
                objective=objective, target=target,
                phases=phases,
                metadata={"raw_response": response}
            )
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            logger.error("plan_parse_failed", error=str(e), response=response)
            # Fallback: create a simple scan→exploit plan
            return self._fallback_plan(objective, target)

    def _fallback_plan(self, objective: str, target: Optional[str]) -> MissionPlan:
        return MissionPlan(
            objective=objective, target=target,
            phases=[
                MissionPhase("scan", "Port scan the target", "scanner",
                            {"target": target} if target else {}),
                MissionPhase("osint", "Gather OSINT", "osint",
                            {"target": target} if target else {}),
                MissionPhase("exploit", "Attempt exploitation", "exploit", {},
                            depends_on=["scan", "osint"]),
            ],
            metadata={"fallback": True}
        )
```

**Tests → Commit**

```bash
git add navmax/ai/mission_planner.py tests/test_mission_planner.py
git commit -m "feat(ai): add autonomous mission planner with LLM-driven task decomposition"
```

---

## P3.3 — Audit Trail (Fondation transverse)

**Objectif:** Chaque action (scan, exploit, OSINT collect) est horodatée, journalisée, et liée à une mission.

### Task 3.3.1: Audit log DB model + engine

**Files:**
- Modify: `navmax/db/models.py` — ajouter `AuditEntry`
- Create: `navmax/core/audit.py` — `AuditLogger`
- Create: `tests/test_audit.py`

```python
# navmax/db/models.py — ajout
class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, nullable=False, default=_utcnow)
    mission_id = Column(String(36), ForeignKey("workspaces.id", ondelete="SET NULL"), nullable=True)
    phase_id = Column(String(100), nullable=True)
    action = Column(String(50), nullable=False)  # scan, exploit, osint_collect, proxy_intercept
    module = Column(String(100), nullable=False)  # scanner.tcp, exploit.ssh_bruteforce, etc.
    target = Column(String(500), nullable=True)
    parameters = Column(JSON, nullable=True)  # input params (sanitized)
    result_summary = Column(JSON, nullable=True)  # condensed output
    status = Column(String(20), nullable=False)  # started, completed, failed, rolled_back
    duration_ms = Column(Integer, nullable=True)
    rollback_info = Column(JSON, nullable=True)  # what was done to roll back
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    # Relationships
    mission = relationship("Workspace", back_populates="audit_entries")
```

```python
# navmax/core/audit.py
import time
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional, AsyncIterator
from dataclasses import dataclass, field
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

@dataclass
class AuditContext:
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: Optional[str] = None
    phase_id: Optional[str] = None
    action: str = ""
    module: str = ""
    target: Optional[str] = None
    parameters: Optional[dict] = None
    _start_time: float = field(default_factory=time.monotonic)

class AuditLogger:
    def __init__(self, session: AsyncSession):
        self.session = session

    @asynccontextmanager
    async def track(self, action: str, module: str, *,
                    mission_id: Optional[str] = None,
                    phase_id: Optional[str] = None,
                    target: Optional[str] = None,
                    parameters: Optional[dict] = None) -> AsyncIterator[AuditContext]:
        ctx = AuditContext(
            mission_id=mission_id, phase_id=phase_id,
            action=action, module=module,
            target=target, parameters=parameters
        )
        logger.info("audit_started", **ctx.__dict__)

        try:
            yield ctx
            await self._save(ctx, status="completed")
            logger.info("audit_completed", entry_id=ctx.entry_id)
        except Exception as e:
            await self._save(ctx, status="failed", error=str(e))
            logger.error("audit_failed", entry_id=ctx.entry_id, error=str(e))
            raise

    async def _save(self, ctx: AuditContext, status: str, error: Optional[str] = None):
        from navmax.db.models import AuditEntry
        entry = AuditEntry(
            id=ctx.entry_id,
            mission_id=ctx.mission_id,
            phase_id=ctx.phase_id,
            action=ctx.action,
            module=ctx.module,
            target=ctx.target,
            parameters=ctx.parameters,
            status=status,
            duration_ms=int((time.monotonic() - ctx._start_time) * 1000),
            error=error
        )
        self.session.add(entry)
        await self.session.commit()
```

**Tests → Commit**

---

## P3.4 — Tableau de Bord Cognitif (Web)

**Objectif:** Interface web affichant un graphe de connaissances animé avec les décisions de l'IA.

### Task 3.4.1: Cognitive dashboard backend

**Files:**
- Create: `navmax/api/routes/dashboard.py`
- Create: `navmax/api/static/dashboard.html`

```python
# navmax/api/routes/dashboard.py
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from navmax.db.session import get_session
from navmax.osint.graph.engine import GraphEngine

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return HTMLResponse(open("navmax/api/static/dashboard.html").read())

@router.get("/api/mission/{mission_id}/graph")
async def mission_graph(mission_id: str, session: AsyncSession = Depends(get_session)):
    """Return graph data for cognitive visualization."""
    # Query all entities linked to this mission
    # Return nodes + edges for D3.js force graph
    ...
```

**Commit**

---

# Phase 4 — Perception : Scanner Intelligent + OSINT Augmenté (2 semaines)

> **Dépendance :** P3 (AI Engine)

## P4.1 — Scanner Contextuel et Adaptatif

### Task 4.1.1: ContextualScanEngine

**Objective:** Le scanner détecte un service → lance automatiquement les probes appropriées (SMB → enum shares, HTTP → dir busting, etc.)

**Files:**
- Create: `navmax/scanner/contextual.py`
- Modify: `navmax/scanner/__init__.py`
- Create: `tests/test_contextual_scanner.py`

```python
# navmax/scanner/contextual.py
# Service → action mapping with cascading probes
SERVICE_ACTIONS = {
    80: ["http_dir_scan", "http_tech_fingerprint", "http_vuln_check"],
    443: ["ssl_analyze", "https_dir_scan", "https_tech_fingerprint"],
    445: ["smb_enum_shares", "smb_enum_users", "smb_vuln_check"],
    3306: ["mysql_version_probe", "mysql_bruteforce"],
    6379: ["redis_info_probe", "redis_unauth_check"],
    27017: ["mongodb_list_dbs", "mongodb_unauth_check"],
    22: ["ssh_version_probe", "ssh_bruteforce"],
    8080: ["http_dir_scan", "http_tech_fingerprint", "tomcat_check"],
    # ...
}

class ContextualScanEngine:
    def __init__(self, ai_engine=None):
        self.ai = ai_engine

    async def scan(self, target: str, ports: list[int]) -> dict:
        results = {}
        for port in ports:
            results[port] = await self._scan_port(target, port)
            # Cascading: if HTTP detected, trigger web probes
            if self._is_http(results[port]):
                web_results = await self._web_probes(target, port)
                results[f"{port}_web"] = web_results
        return results
```

### Task 4.1.2: Détection active de vulnérabilités (CVE DB locale)

**Objective:** Base de signatures locales pour matcher service/version → CVE connu

**Files:**
- Create: `navmax/scanner/vuln_db.py`
- Create: `navmax/scanner/data/cve_signatures.json`
- Create: `scripts/update_cve_db.py`

```python
# navmax/scanner/vuln_db.py
import json
from pathlib import Path
from packaging.version import Version
import re

class VulnDatabase:
    def __init__(self, db_path: Path = None):
        self.db_path = db_path or Path(__file__).parent / "data" / "cve_signatures.json"
        self._signatures = None

    def load(self):
        with open(self.db_path) as f:
            self._signatures = json.load(f)

    def check(self, service: str, version: str) -> list[dict]:
        """Return list of CVEs matching service+version."""
        matches = []
        for sig in self._signatures:
            if sig["service"].lower() != service.lower():
                continue
            if self._version_in_range(version, sig.get("version_range", "*")):
                matches.append(sig)
        return matches

    def _version_in_range(self, version: str, range_spec: str) -> bool:
        if range_spec == "*":
            return True
        # Parse range like ">=2.4.0,<2.4.50"
        ...
```

```json
// navmax/scanner/data/cve_signatures.json
[
  {
    "cve": "CVE-2021-41773",
    "service": "apache",
    "version_range": ">=2.4.49,<2.4.51",
    "severity": "HIGH",
    "description": "Path traversal in Apache HTTP Server 2.4.49-2.4.50",
    "exploit_module": null,
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
  }
]
```

**Tests → Commit**

---

## P4.2 — OSINT Augmenté

### Task 4.2.1: OSINT Continu avec Alertes

**Objective:** "Abonnement" à un domaine/IP — collectes périodiques + alertes sur changements

**Files:**
- Create: `navmax/osint/monitor.py` — `OSINTMonitor`
- Modify: `navmax/db/models.py` — `MonitorSubscription`
- Create: `tests/test_osint_monitor.py`

```python
# navmax/osint/monitor.py
class OSINTMonitor:
    def __init__(self, session, orchestrator, notifier=None):
        self.session = session
        self.orchestrator = orchestrator  # existing OSINT orchestrator
        self.notifier = notifier  # Telegram, Slack, email

    async def subscribe(self, target: str, interval_hours: int = 24, alert_on: list[str] = None):
        """Create a monitoring subscription."""
        ...

    async def check_all(self):
        """Run all active subscriptions, detect changes, send alerts."""
        ...
```

### Task 4.2.2: Recherche Sémantique sur le Graphe

**Objective:** Interroger le graphe NetworkX en langage naturel via l'IA

**Files:**
- Create: `navmax/osint/graph/semantic_search.py`
- Create: `tests/test_semantic_search.py`

```python
# navmax/osint/graph/semantic_search.py
class SemanticGraphSearch:
    def __init__(self, graph_engine, ai_engine):
        self.graph = graph_engine
        self.ai = ai_engine

    async def search(self, query: str) -> dict:
        """Natural language → Cypher-like query → graph results."""
        # Step 1: LLM translates NL to graph operations
        ops = await self._translate_query(query)
        # Step 2: Execute graph operations
        results = self._execute_ops(ops)
        # Step 3: LLM formats results in natural language
        summary = await self._format_results(query, results)
        return {"raw": results, "summary": summary}
```

### Task 4.2.3: Intégration Leaks (HIBP API + Dehashed)

**Objective:** Enrichir le graphe avec des données de breaches

**Files:**
- Create: `navmax/osint/collectors/leaks.py`
- Modify: `navmax/osint/collectors/__init__.py`

**Tests → Commit**

---

# Phase 5 — Action : Exploit Génératif + Pivot Auto + Évasion (3 semaines)

> **Dépendance :** P3 (AI Engine) + P4 (Scanner intelligent pour fournir les infos de service)

## P5.1 — Générateur d'Exploits par IA

### Task 5.1.1: AIExploitGenerator

**Objective:** Face à un service inconnu, l'IA génère un exploit Python sur mesure en analysant la bannière/réponse.

**Files:**
- Create: `navmax/exploit/ai_generator.py`
- Create: `tests/test_ai_exploit_generator.py`

```python
# navmax/exploit/ai_generator.py
class AIExploitGenerator:
    def __init__(self, ai_engine, sandbox):
        self.ai = ai_engine
        self.sandbox = sandbox

    async def generate(self, service_info: dict) -> Optional[str]:
        """
        service_info = {
            "host": "10.0.0.1",
            "port": 8080,
            "service": "Apache",
            "version": "2.4.49",
            "banner": "Apache/2.4.49 (Ubuntu)",
            "error_response": "...",
            "vulnerabilities": [{"cve": "CVE-2021-41773", ...}]
        }
        """
        # Step 1: LLM generates exploit code
        code = await self.ai.generate(
            f"Generate a Python exploit for {service_info}",
            system=EXPLOIT_GENERATOR_SYSTEM,
            temperature=0.4
        )

        # Step 2: Extract code from response
        exploit_code = self._extract_code(code)

        # Step 3: Test in sandbox (dry-run, no target)
        result = await self.sandbox.run(exploit_code, language="python")
        if result.exit_code != 0:
            # Step 4: Self-heal — ask LLM to fix
            fixed = await self._self_heal(exploit_code, result.stderr)
            return fixed

        return exploit_code

    async def _self_heal(self, code: str, error: str) -> Optional[str]:
        fixed = await self.ai.generate(
            f"This Python code failed with error:\n{error}\n\nCode:\n{code}\n\nFix it.",
            temperature=0.3
        )
        return self._extract_code(fixed)
```

**Tests → Commit**

---

## P5.2 — Pivot Automatique (Lateral Movement)

### Task 5.2.1: AutoPivot Engine

**Objective:** Une fois un accès obtenu, scanner le réseau interne depuis la machine compromise et proposer les prochaines cibles.

**Files:**
- Create: `navmax/exploit/auto_pivot.py`
- Create: `tests/test_auto_pivot.py`

```python
# navmax/exploit/auto_pivot.py
class AutoPivotEngine:
    def __init__(self, scanner, ai_engine, mission_planner):
        self.scanner = scanner
        self.ai = ai_engine
        self.planner = mission_planner

    async def pivot(self, session_info: dict) -> MissionPlan:
        """
        session_info = {
            "host": "10.0.0.5",  # compromised host
            "access_type": "ssh",
            "internal_network": "10.0.1.0/24",
            "current_user": "www-data",
            "discovered_creds": [...]
        }
        """
        # Step 1: Scan internal network from compromised host
        internal_hosts = await self._internal_scan(session_info)

        # Step 2: AI analyzes and recommends next targets
        next_targets = await self._analyze_targets(internal_hosts, session_info)

        # Step 3: Generate new mission phases
        plan = await self.planner.plan(
            f"Pivot from {session_info['host']} to high-value targets",
            target=",".join(next_targets)
        )
        return plan
```

---

## P5.3 — Moteur d'Évasion Intelligent

### Task 5.3.1: PolymorphicMutationEngine

**Objective:** Mutation aléatoire des payloads à chaque exécution (renommage variables, code mort, chiffrement dynamique)

**Files:**
- Create: `navmax/exploit/evasion.py`
- Modify: `navmax/exploit/encoders.py` — intégrer la mutation
- Create: `tests/test_evasion.py`

```python
# navmax/exploit/evasion.py
import ast
import random
import string

class PolymorphicMutationEngine:
    """Mutates Python exploit code to evade signature-based AV."""

    def __init__(self, seed=None):
        self.rng = random.Random(seed)

    def mutate(self, code: str, iterations: int = 3) -> str:
        tree = ast.parse(code)
        for _ in range(iterations):
            tree = self._apply_random_mutation(tree)
        return ast.unparse(tree)

    def _apply_random_mutation(self, tree):
        mutations = [
            self._rename_variables,
            self._add_dead_code,
            self._reorder_independent_stmts,
            self._split_strings,
        ]
        return self.rng.choice(mutations)(tree)

    def _rename_variables(self, tree):
        """Rename all variables to random strings."""
        ...

    def _add_dead_code(self, tree):
        """Insert unreachable code blocks."""
        ...

    def _split_strings(self, tree):
        """Split string literals: 'exploit' → chr(101)+chr(120)+..."""
        ...
```

**Tests → Commit**

---

# Phase 6 — Orchestration : One-Click + Rapports + Connecteurs (2 semaines)

> **Dépendance :** P3-P5

## P6.1 — Interface "One-Click Mission"

### Task 6.1.1: Mission orchestrator CLI + API

**Objective:** Un seul point d'entrée : `navmax mission "Trouve la base de données sensible sur le réseau 10.0.0.0/24"`

**Files:**
- Create: `navmax/orchestrator/__init__.py`
- Create: `navmax/orchestrator/engine.py`
- Modify: `navmax/cli.py`
- Create: `navmax/api/routes/missions.py`

```python
# navmax/orchestrator/engine.py
class MissionOrchestrator:
    """One-click mission: plan → execute → report."""

    def __init__(self, ai_engine, planner, scanner, exploit_loader, osint_orch, audit):
        self.ai = ai_engine
        self.planner = planner
        self.scanner = scanner
        self.exploits = exploit_loader
        self.osint = osint_orch
        self.audit = audit

    async def execute(self, objective: str, target: Optional[str] = None) -> MissionResult:
        # Step 1: Plan
        plan = await self.planner.plan(objective, target)

        # Step 2: Execute phases in dependency order
        results = {}
        for phase in self._topological_sort(plan.phases):
            async with self.audit.track(phase.module_needed, phase.id, ...):
                result = await self._execute_phase(phase, results)
                results[phase.id] = result

        # Step 3: Generate report
        report = await self._generate_report(objective, plan, results)
        return MissionResult(plan=plan, results=results, report=report)
```

```python
# navmax/cli.py — ajout
@app.command()
def mission(objective: str, target: Optional[str] = None):
    """Execute a one-click autonomous mission."""
    ...
```

---

## P6.2 — Export de Rapports IA

### Task 6.2.1: AI Report Generator (PDF/DOCX/HTML)

**Files:**
- Create: `navmax/reporting/__init__.py`
- Create: `navmax/reporting/generator.py`
- Create: `navmax/reporting/templates/`
- Modify: `pyproject.toml` — add `weasyprint`, `python-docx`

---

## P6.3 — Connecteurs SIEM/SOAR

### Task 6.3.1: TheHive + MISP connectors

**Files:**
- Create: `navmax/integrations/__init__.py`
- Create: `navmax/integrations/thehive.py`
- Create: `navmax/integrations/misp.py`

---

## P6.4 — Mode Air Gap

### Task 6.4.1: Offline-first packaging

**Objective:** Tout fonctionne sans internet — modèles Ollama locaux, CVE DB locale, pas de dépendances cloud.

**Files:**
- Create: `scripts/airgap_bundle.py` — package tout
- Create: `scripts/verify_airgap.py` — smoke test offline

---

# Synthèse des Phases

| Phase | Nom | Tâches | Tests | Points clés |
|---|---|---|---|---|---|
| **P3** | Cerveau | 12-15 | 35+ | **6 providers** (Ollama/llama.cpp/LM Studio/OpenAI/Anthropic/DeepSeek), **3 tiers** (Light ≤3B / Medium 7-8B / Heavy 70B+), auto-détection hardware, airgap mode, Mission Planner, Audit Trail, Dashboard |
| **P4** | Perception | 8-10 | 20+ | Scanner contextuel, CVE DB, OSINT continu, Semantic Search, Leaks |
| **P5** | Action | 6-8 | 18+ | AI Exploit Gen, Auto-Pivot, Évasion polymorphique |
| **P6** | Orchestration | 6-8 | 15+ | One-Click, Rapports IA, SIEM/SOAR, Air Gap |

**Total estimé : 32-41 tâches, 88+ nouveaux tests, 10-12 semaines.**

### Compatibilité Hardware — de la machine modeste au serveur

| Configuration | RAM | GPU | Tiers locaux | Tiers cloud |
|---|---|---|---|---|
| Mini PC / vieux laptop | 4-8 GB | ❌ | Light (3B) uniquement | Medium + Heavy |
| Laptop standard | 16 GB | ❌ | Light + Medium (7-8B) | Heavy |
| PC gamer | 32 GB | RTX 3060+ | Light + Medium + Heavy (Q4) | Optionnel |
| Station de travail | 64 GB | RTX 4090 | Tout en local (Q8) | Désactivé |
| **Mode Air Gap** | 32+ GB | RTX 3060+ | Light + Medium + Heavy | **Bloqué** |

---

# Vérification par Phase

Chaque phase validée par :
1. `pytest tests/ -v --tb=short` — 100% pass
2. Test manuel de bout en bout (scénario documenté)
3. Revue de code via `requesting-code-review`

---

# Risques et Mitigations

| Risque | Impact | Mitigation |
|---|---|---|---|
| **Hardware insuffisant pour le tier demandé** | Bloquant P3 | Fallback automatique : Light→Medium→Heavy avec dégradation gracieuse. Cloud optionnel. |
| **Ollama non installé** | P3 sans provider local | Fallback vers LM Studio ou llama.cpp. Guide d'install automatique (`navmax setup`). |
| **GPU non détecté correctement** | Perf suboptimale | Fallback CPU + GGUF Q4. Détection nvidia-smi + Apple Silicon. |
| Génération d'exploit IA imprécise | P5 inefficace | Sandbox de validation + self-heal loop |
| Faux positifs scanner contextuel | P4 bruyant | Whitelist progressive des probes |
| Complexité auto-pivot | P5 instable | Scope limits explicites, kill-switch |
