"""Routes API pour la gestion des API keys (settings).

Endpoints:
    GET    /api/v1/settings/apikeys       — liste toutes les clés (masquées)
    POST   /api/v1/settings/apikeys       — sauvegarder une clé
    DELETE /api/v1/settings/apikeys/{provider} — supprimer une clé
"""

import os
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from navmax.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])

# ── Chemin du fichier YAML ──────────────────────────────────────
API_KEYS_DIR = Path.home() / ".navmax"
API_KEYS_FILE = API_KEYS_DIR / "api_keys.yaml"


# ── Schemas ─────────────────────────────────────────────────────


class ApiKeySaveRequest(BaseModel):
    """Requête pour sauvegarder une API key."""
    provider: str = Field(
        ...,
        description="Nom du provider (deepseek, openai, anthropic)",
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    key: str = Field(..., min_length=1, description="La clé API en clair")


class ApiKeyInfo(BaseModel):
    """Informations sur une API key (clé masquée)."""
    provider: str
    configured: bool
    key_preview: str = Field(
        "",
        description="Aperçu masqué de la clé (ex: deep****pro)",
    )


class ApiKeyListResponse(BaseModel):
    """Liste des API keys configurées."""
    providers: list[ApiKeyInfo] = []


class ApiKeySaveResponse(BaseModel):
    """Réponse après sauvegarde d'une API key."""
    status: str = "saved"
    provider: str
    message: str = ""


class ApiKeyDeleteResponse(BaseModel):
    """Réponse après suppression d'une API key."""
    status: str = "deleted"
    provider: str


# ── Helpers ─────────────────────────────────────────────────────


def _mask_key(key: str) -> str:
    """Masque une clé API : garde les 4 premiers et 3 derniers chars."""
    if len(key) <= 10:
        return key[:4] + "****"
    return key[:4] + "****" + key[-3:]


async def _load_keys() -> dict:
    """Charge les clés depuis le fichier YAML de manière asynchrone."""
    try:
        import aiofiles

        if not API_KEYS_FILE.exists():
            return {"providers": {}}
        async with aiofiles.open(API_KEYS_FILE, "r", encoding="utf-8") as f:
            content = await f.read()
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or "providers" not in data:
            return {"providers": {}}
        return data
    except Exception as exc:
        logger.warning("api_keys_lecture_erreur", erreur=str(exc))
        return {"providers": {}}


async def _save_keys(data: dict) -> None:
    """Sauvegarde les clés dans le fichier YAML de manière asynchrone."""
    try:
        import aiofiles

        API_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        content = yaml.safe_dump(data, default_flow_style=False, allow_unicode=True)
        async with aiofiles.open(API_KEYS_FILE, "w", encoding="utf-8") as f:
            await f.write(content)
        # Ne jamais logger les clés en clair
        providers = list(data.get("providers", {}).keys())
        logger.info("api_keys_sauvegardées", providers=providers)
    except Exception as exc:
        logger.exception("api_keys_sauvegarde_erreur", erreur=str(exc))
        raise


# ── Routes ──────────────────────────────────────────────────────


@router.get(
    "/apikeys",
    response_model=ApiKeyListResponse,
    summary="Liste toutes les API keys configurées (masquées)",
    description="Retourne la liste des providers avec leurs clés masquées.",
    responses={
        200: {"description": "Liste des API keys"},
    },
)
async def list_api_keys() -> ApiKeyListResponse:
    """Liste toutes les clés API configurées, avec aperçu masqué."""
    data = await _load_keys()
    providers_data = data.get("providers", {})

    providers_list = []
    for provider, key in providers_data.items():
        providers_list.append(
            ApiKeyInfo(
                provider=provider,
                configured=True,
                key_preview=_mask_key(key),
            )
        )

    return ApiKeyListResponse(providers=providers_list)


@router.post(
    "/apikeys",
    response_model=ApiKeySaveResponse,
    summary="Sauvegarde une API key",
    description="Ajoute ou met à jour une API key pour un provider.",
    status_code=201,
    responses={
        201: {"description": "Clé sauvegardée"},
        400: {"description": "Requête invalide"},
    },
)
async def save_api_key(req: ApiKeySaveRequest) -> ApiKeySaveResponse:
    """Sauvegarde (ajoute ou met à jour) une API key pour un provider."""
    provider = req.provider.strip().lower()
    key = req.key.strip()

    if not key:
        raise HTTPException(400, "La clé API ne peut pas être vide")

    data = await _load_keys()

    if "providers" not in data:
        data["providers"] = {}

    data["providers"][provider] = key
    await _save_keys(data)

    logger.info("api_key_sauvegardée", provider=provider)

    return ApiKeySaveResponse(
        status="saved",
        provider=provider,
        message=f"Clé API pour '{provider}' sauvegardée.",
    )


@router.delete(
    "/apikeys/{provider}",
    response_model=ApiKeyDeleteResponse,
    summary="Supprime une API key",
    description="Supprime la clé API pour un provider donné.",
    responses={
        200: {"description": "Clé supprimée"},
        404: {"description": "Provider non trouvé"},
    },
)
async def delete_api_key(provider: str) -> ApiKeyDeleteResponse:
    """Supprime une API key pour un provider donné."""
    provider = provider.strip().lower()

    data = await _load_keys()
    providers_data = data.get("providers", {})

    if provider not in providers_data:
        raise HTTPException(404, f"Aucune clé trouvée pour le provider '{provider}'")

    del providers_data[provider]
    data["providers"] = providers_data
    await _save_keys(data)

    logger.info("api_key_supprimée", provider=provider)

    return ApiKeyDeleteResponse(status="deleted", provider=provider)
