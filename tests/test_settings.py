"""Tests pour la gestion des API keys (routes settings)."""

from unittest.mock import AsyncMock, patch
import pytest
import yaml
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from navmax.api.routes.settings import _mask_key, router


@pytest.fixture
def test_app():
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
async def client(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_storage():
    """Remplace _load_keys et _save_keys par des mocks."""
    storage = {"providers": {}}

    async def fake_load():
        return storage

    async def fake_save(data):
        storage.clear()
        storage.update(data)

    with patch(
        "navmax.api.routes.settings._load_keys",
        side_effect=fake_load,
    ) as ml:
        with patch(
            "navmax.api.routes.settings._save_keys",
            side_effect=fake_save,
        ) as ms:
            yield ml, ms, storage


class TestMaskKey:
    def test_masque_cle_longue(self):
        assert _mask_key("sk-dee...-pro") == "sk-d****pro"

    def test_masque_cle_courte(self):
        assert _mask_key("abc123") == "abc1****"

    def test_masque_cle_vide(self):
        assert _mask_key("") == "****"


class TestListApiKeys:
    async def test_liste_vide(self, client, mock_storage):
        resp = await client.get("/apikeys")
        assert resp.status_code == 200
        data = resp.json()
        assert data["providers"] == []

    async def test_liste_avec_cles(self, client, mock_storage):
        _, _, storage = mock_storage
        storage["providers"]["deepseek"] = "sk-dee...-123"
        storage["providers"]["openai"] = "sk-old-key"
        resp = await client.get("/apikeys")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["providers"]) == 2
        d = [p for p in data["providers"] if p["provider"] == "deepseek"][0]
        assert d["configured"] is True
        assert "sk-dee...-123" not in d["key_preview"]


class TestSaveApiKey:
    async def test_sauvegarder_cle(self, client, mock_storage):
        _, _, storage = mock_storage
        storage["providers"]["openai"] = "sk-old-key"
        resp = await client.post(
            "/apikeys",
            json={"provider": "deepseek", "key": "sk-dee...-key"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "saved"
        assert storage["providers"]["deepseek"] == "sk-dee...-key"
        assert storage["providers"]["openai"] == "sk-old-key"

    async def test_cle_vide_refusee(self, client, mock_storage):
        resp = await client.post(
            "/apikeys",
            json={"provider": "deepseek", "key": "   "},
        )
        assert resp.status_code == 400

    async def test_provider_invalide_refuse(self, client, mock_storage):
        resp = await client.post(
            "/apikeys",
            json={"provider": "", "key": "sk-test"},
        )
        assert resp.status_code == 422


class TestDeleteApiKey:
    async def test_supprimer_cle_existante(self, client, mock_storage):
        _, _, storage = mock_storage
        storage["providers"]["deepseek"] = "sk-key-1"
        storage["providers"]["openai"] = "sk-key-2"
        resp = await client.delete("/apikeys/deepseek")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "deleted"
        assert "deepseek" not in storage["providers"]
        assert "openai" in storage["providers"]

    async def test_supprimer_cle_inexistante(self, client, mock_storage):
        _, _, storage = mock_storage
        storage["providers"] = {}
        resp = await client.delete("/apikeys/deepseek")
        assert resp.status_code == 404


class TestMaskFunction:
    def test_masque_cle_exactement_10_caracteres(self):
        assert _mask_key("1234567890") == "1234****"

    def test_masque_cle_longue_avec_special_chars(self):
        assert _mask_key("sk-ant...-abc") == "sk-a****abc"

    def test_masque_cle_ne_logge_pas_la_cle(self):
        key = "sk-sup...2345"
        masked = _mask_key(key)
        assert key not in masked
        assert len(masked) < len(key)
