"""Routes API pour le module IA.

Endpoints:
    GET  /api/v1/ai/status   — état du moteur IA (providers, hardware, modèles)
    POST /api/v1/ai/generate — génération avec sélection automatique
    POST /api/v1/ai/stream   — streaming SSE
    GET  /api/v1/ai/models   — liste tous les modèles dispo
    POST /api/v1/ai/reload   — réinitialise les providers
"""

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from navmax.ai.engine import get_engine
from navmax.ai.providers.base import ModelTier, ProviderType
from navmax.core.logging import get_logger

router = APIRouter(prefix="/api/v1/ai", tags=["AI"])
logger = get_logger(__name__)


# ── Schemas ──────────────────────────────────────────────────────


class GenerateRequest(BaseModel):
    prompt: str
    tier: str = Field(default="medium", description="light | medium | heavy")
    system: str | None = None
    max_tokens: int = Field(default=2048, le=8192)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    json_mode: bool = False
    provider: str | None = None  # ollama | openai | anthropic | deepseek
    model: str | None = None  # forcer un modèle spécifique


class GenerateResponse(BaseModel):
    text: str
    model: str
    provider: str
    tier: str
    tokens_used: int
    tokens_per_second: float
    finish_reason: str


# ── Routes ───────────────────────────────────────────────────────


@router.get("/status")
async def ai_status():
    """État complet du moteur IA."""
    engine = get_engine()
    if not engine._initialized:
        await engine.initialize()
    return await engine.get_status()


@router.post("/generate", response_model=GenerateResponse)
async def ai_generate(req: GenerateRequest):
    """Génération avec sélection automatique du meilleur modèle."""
    engine = get_engine()
    if not engine._initialized:
        await engine.initialize()

    try:
        tier = ModelTier(req.tier)
    except ValueError:
        raise HTTPException(400, f"Tier invalide: {req.tier}. Valides: light, medium, heavy")

    provider = None
    if req.provider:
        try:
            provider = ProviderType(req.provider)
        except ValueError:
            raise HTTPException(400, f"Provider invalide: {req.provider}")

    try:
        result = await engine.generate(
            prompt=req.prompt,
            tier=tier,
            system=req.system,
            max_tokens=req.max_tokens,
            temperature=req.temperature,
            json_mode=req.json_mode,
            provider=provider,
            model=req.model,
        )
        logger.info(
            "ai_génération_réussie",
            model=result.model,
            provider=result.provider.value,
            tier=tier.value,
            tokens=result.tokens_used,
        )
        return GenerateResponse(
            text=result.text,
            model=result.model,
            provider=result.provider.value,
            tier=tier.value,
            tokens_used=result.tokens_used,
            tokens_per_second=result.tokens_per_second,
            finish_reason=result.finish_reason,
        )
    except RuntimeError as e:
        logger.exception("ai_génération_échouée", erreur=str(e), tier=tier.value)
        raise HTTPException(503, str(e))


@router.post("/stream")
async def ai_stream(req: GenerateRequest):
    """Streaming SSE — chaque chunk est envoyé en temps réel."""
    engine = get_engine()
    if not engine._initialized:
        await engine.initialize()

    try:
        tier = ModelTier(req.tier)
    except ValueError:
        raise HTTPException(400, f"Tier invalide: {req.tier}")

    provider = None
    if req.provider:
        try:
            provider = ProviderType(req.provider)
        except ValueError:
            raise HTTPException(400, f"Provider invalide: {req.provider}")

    async def event_stream():
        try:
            async for chunk in engine.stream(
                prompt=req.prompt,
                tier=tier,
                system=req.system,
                max_tokens=req.max_tokens,
                temperature=req.temperature,
                provider=provider,
                model=req.model,
            ):
                yield f"data: {json.dumps({'chunk': chunk})}\n\n"
            yield "data: [DONE]\n\n"
        except RuntimeError as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/models")
async def list_models():
    """Liste tous les modèles disponibles, par provider."""
    engine = get_engine()
    if not engine._initialized:
        await engine.initialize()

    models = []
    if engine._selector:
        for result in engine._selector._available.values():
            models.append(
                {
                    "name": result.model,
                    "provider": result.provider.value,
                    "tier": result.tier.value,
                    "uncensored": result.is_uncensored,
                    "local": result.is_local,
                    "reason": result.reason,
                },
            )

    # Trier: local d'abord, puis uncensored, puis par tier
    models.sort(
        key=lambda m: (
            0 if m["local"] else 1,
            0 if m["uncensored"] else 1,
            {"light": 0, "medium": 1, "heavy": 2}[m["tier"]],
        ),
    )

    return {"models": models}


@router.post("/reload")
async def reload_engine():
    """Réinitialise tous les providers (après changement de config ou install de modèle)."""
    logger.info("ai_engine_rechargement")
    engine = get_engine()
    status = await engine.reload()
    logger.info("ai_engine_rechargé")
    return status
