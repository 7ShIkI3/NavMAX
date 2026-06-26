"""Tests de la couche sécurité NavMAX : JWT, RBAC, rate limiting, et validation d'entrées.

Tests :
  - test_jwt_encode_decode              : encodage/décodage token JWT
  - test_password_hash                  : hash/verify passlib
  - test_login_endpoint_success         : /api/v1/auth/login → token
  - test_login_endpoint_invalid         : mauvais credentials → 401
  - test_register_endpoint              : /api/v1/auth/register
  - test_register_duplicate             : username déjà pris → 409
  - test_me_endpoint                    : /api/v1/auth/me avec token
  - test_unauthorized_access            : route protégée sans token → 401
  - test_rbac_admin_required            : viewer ne peut pas accéder à /exploit → 403
  - test_rbac_operator_can_access_ai     : operator peut accéder à /ai → 200
  - test_health_public                  : /api/v1/health sans token → 200
  - test_docs_public                    : /docs sans token → 200
"""

import pytest
from fastapi.testclient import TestClient

# ── Setup : configurer AVANT d'importer l'app ──────────────────
from navmax.core.config import config as _cfg

_cfg.redis_url = ""  # Pas de Redis en test → fallback in-memory

# HACK: s'assurer que les tables DB existent (le lifespan de TestClient ne les crée pas)
import asyncio as _asyncio
from datetime import UTC

from navmax.api.app import app
from navmax.api.auth import _users_db, create_user
from navmax.db import create_all as _create_all

_asyncio.run(_create_all())


# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_users() -> None:
    """Nettoie et recrée les utilisateurs par défaut avant chaque test."""
    _users_db.clear()
    create_user("admin", "admin123", "admin")
    create_user("operator", "operator123", "operator")
    create_user("viewer", "viewer123", "viewer")


@pytest.fixture
def client():
    """TestClient FastAPI."""
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    """Token JWT pour l'utilisateur admin."""
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "admin123",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def operator_token(client):
    """Token JWT pour l'utilisateur operator."""
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "username": "operator",
            "password": "operator123",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def viewer_token(client):
    """Token JWT pour l'utilisateur viewer."""
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "username": "viewer",
            "password": "viewer123",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


# ══════════════════════════════════════════════════════════════
# JWT unitaires
# ══════════════════════════════════════════════════════════════


class TestJWT:
    def test_jwt_encode_decode(self) -> None:
        """Encodage et décodage JWT."""
        from navmax.api.auth import create_access_token, decode_access_token

        token = create_access_token({"sub": "testuser", "role": "admin"})
        assert isinstance(token, str)
        assert len(token) > 20

        payload = decode_access_token(token)
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"

    def test_jwt_expiry(self) -> None:
        """Un token expiré est rejeté."""
        from datetime import datetime, timedelta

        from fastapi import HTTPException
        from jose import jwt

        from navmax.api.auth import ALGORITHM, SECRET_KEY, decode_access_token

        # Créer un token déjà expiré (dans le passé)
        expired_payload = {
            "sub": "test",
            "role": "admin",
            "exp": datetime.now(UTC) - timedelta(hours=1),
        }
        expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(expired_token)
        assert exc_info.value.status_code == 401

    def test_password_hash(self) -> None:
        """Hash bcrypt et vérification."""
        from navmax.api.auth import hash_password, verify_password

        hashed = hash_password("s3cur3-p@ss")
        assert hashed != "s3cur3-p@ss"
        assert verify_password("s3cur3-p@ss", hashed) is True
        assert verify_password("wrong-password", hashed) is False


# ══════════════════════════════════════════════════════════════
# Login endpoint
# ══════════════════════════════════════════════════════════════


class TestLoginEndpoint:
    def test_login_success_admin(self, client) -> None:
        """Connexion admin → 200 + token + rôle admin."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "admin",
                "password": "admin123",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "admin"

    def test_login_success_operator(self, client) -> None:
        """Connexion operator → 200."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "operator",
                "password": "operator123",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "operator"

    def test_login_success_viewer(self, client) -> None:
        """Connexion viewer → 200."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "viewer",
                "password": "viewer123",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"

    def test_login_invalid_username(self, client) -> None:
        """Mauvais username → 401."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "inexistant",
                "password": "admin123",
            },
        )
        assert resp.status_code == 401

    def test_login_wrong_password(self, client) -> None:
        """Mauvais mot de passe → 401."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "admin",
                "password": "wrong-password",
            },
        )
        assert resp.status_code == 401

    def test_login_empty_body(self, client) -> None:
        """Requête vide → 422 (validation Pydantic)."""
        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 422

    def test_login_missing_password(self, client) -> None:
        """Mot de passe manquant → 422."""
        resp = client.post("/api/v1/auth/login", json={"username": "admin"})
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════
# Register endpoint
# ══════════════════════════════════════════════════════════════


class TestRegisterEndpoint:
    def test_register_success(self, client) -> None:
        """Inscription valide → 201 + compte créé."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "new_user",
                "password": "secure-password-123",
                "role": "operator",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["username"] == "new_user"
        assert resp.json()["role"] == "operator"

        # Vérifier que le nouvel utilisateur peut se connecter
        login_resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "new_user",
                "password": "secure-password-123",
            },
        )
        assert login_resp.status_code == 200

    def test_register_default_role(self, client) -> None:
        """Inscription sans rôle → rôle viewer par défaut."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "default_role_user",
                "password": "secure-password-123",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "viewer"

    def test_register_duplicate(self, client) -> None:
        """Inscription avec username existant → 409."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "admin",
                "password": "secure-password-123",
            },
        )
        assert resp.status_code == 409

    def test_register_invalid_role(self, client) -> None:
        """Rôle invalide → 422."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "hacker",
                "password": "secure-password-123",
                "role": "superadmin",
            },
        )
        assert resp.status_code == 422

    def test_register_short_password(self, client) -> None:
        """Mot de passe trop court → 422."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "shortpwd",
                "password": "123",
            },
        )
        assert resp.status_code == 422

    def test_register_invalid_username_chars(self, client) -> None:
        """Username avec caractères spéciaux → 422."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "user@name!",
                "password": "secure-password-123",
            },
        )
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════
# Me endpoint
# ══════════════════════════════════════════════════════════════


class TestMeEndpoint:
    def test_me_with_valid_token(self, client, admin_token) -> None:
        """/me avec token valide → 200 + infos utilisateur."""
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_me_without_token(self, client) -> None:
        """/me sans token → 401."""
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_me_with_invalid_token(self, client) -> None:
        """/me avec token invalide → 401."""
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token-123"},
        )
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════
# RBAC
# ══════════════════════════════════════════════════════════════


class TestRBAC:
    def test_unauthorized_no_token(self, client) -> None:
        """Route protégée sans token → 401."""
        resp = client.get("/api/v1/targets/")
        assert resp.status_code == 401

    def test_viewer_cannot_access_exploit(self, client, viewer_token) -> None:
        """Viewer ne peut pas accéder à /exploit (admin only) → 403."""
        resp = client.get(
            "/api/v1/exploit/search",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403

    def test_operator_cannot_access_exploit(self, client, operator_token) -> None:
        """Operator ne peut pas accéder à /exploit (admin only) → 403."""
        resp = client.get(
            "/api/v1/exploit/search",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_access_exploit(self, client, admin_token) -> None:
        """Admin peut accéder à /exploit/search."""
        resp = client.get(
            "/api/v1/exploit/search",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 422)

    def test_viewer_cannot_access_ad(self, client, viewer_token) -> None:
        """Viewer ne peut pas accéder à /ad (admin only) → 403."""
        resp = client.post(
            "/api/v1/ad/enumerate",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={"server": "dc01.corp.local", "domain": "corp.local"},
        )
        assert resp.status_code == 403

    def test_admin_can_access_ad_enumerate(self, client, admin_token) -> None:
        """Admin peut accéder à /ad/enumerate."""
        resp = client.post(
            "/api/v1/ad/enumerate",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"server": "dc01.corp.local", "domain": "corp.local"},
        )
        # Si le DC n'existe pas, l'erreur est 500 (pas un 403)
        assert resp.status_code in (200, 500)

    def test_viewer_cannot_access_firewall(self, client, viewer_token) -> None:
        """Viewer ne peut pas accéder à /firewall (admin only) → 403."""
        resp = client.post(
            "/api/v1/firewall/analyze",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={"vendor": "fortinet", "hostname": "fgt01", "rules": []},
        )
        assert resp.status_code == 403

    def test_viewer_cannot_access_proxy(self, client, viewer_token) -> None:
        """Viewer ne peut pas accéder à /proxy (admin only) → 403."""
        resp = client.get(
            "/api/v1/proxy/status",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403

    def test_viewer_cannot_access_ai(self, client, viewer_token) -> None:
        """Viewer ne peut pas accéder à /ai (operator+ only) → 403."""
        resp = client.get(
            "/api/v1/ai/status",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403

    def test_operator_can_access_ai(self, client, operator_token) -> None:
        """Operator peut accéder à /ai/status."""
        resp = client.get(
            "/api/v1/ai/status",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code in (200, 503)

    def test_viewer_can_access_targets(self, client, viewer_token) -> None:
        """Viewer peut accéder à /targets (lecture) → 200."""
        resp = client.get(
            "/api/v1/targets/",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200

    def test_viewer_can_access_scans(self, client, viewer_token) -> None:
        """Viewer peut accéder à /scans (lecture) → 200."""
        resp = client.get(
            "/api/v1/scans/",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200

    def test_viewer_can_access_osint(self, client, viewer_token) -> None:
        """Viewer peut accéder à /osint → 200."""
        resp = client.get(
            "/api/v1/osint/transforms",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200

    def test_viewer_can_access_workspaces(self, client, viewer_token) -> None:
        """Viewer peut accéder à /workspaces → 200."""
        resp = client.get(
            "/api/v1/workspaces/",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════
# Routes publiques
# ══════════════════════════════════════════════════════════════


class TestPublicRoutes:
    def test_health_public(self, client) -> None:
        """Health check sans auth → 200."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "version": "0.1.0"}

    def test_docs_public(self, client) -> None:
        """Documentation /docs sans auth → 200."""
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_redoc_public(self, client) -> None:
        """Redoc sans auth → 200."""
        resp = client.get("/redoc")
        assert resp.status_code == 200

    def test_openapi_schema_public(self, client) -> None:
        """Schema OpenAPI sans auth → 200."""
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        assert "paths" in resp.json()
        # Vérifier que les routes d'auth sont dans le schema
        paths = resp.json()["paths"]
        assert "/api/v1/auth/login" in paths
        assert "/api/v1/auth/register" in paths
        assert "/api/v1/auth/me" in paths

    def test_login_route_public_no_auth(self, client) -> None:
        """Login est accessible sans token → 200 (avec bons credentials)."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "admin",
                "password": "admin123",
            },
        )
        assert resp.status_code == 200

    def test_register_route_public_no_auth(self, client) -> None:
        """Register est accessible sans token → 201."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "public_reg",
                "password": "secure-password-123",
            },
        )
        assert resp.status_code == 201


# ══════════════════════════════════════════════════════════════
# Validation des entrées
# ══════════════════════════════════════════════════════════════


class TestInputValidation:
    def test_login_empty_username(self, client) -> None:
        """Username vide → 422."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "",
                "password": "admin123",
            },
        )
        assert resp.status_code == 422

    def test_login_invalid_type(self, client) -> None:
        """Mauvais type de champ → 422."""
        resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": 123,
                "password": "admin123",
            },
        )
        assert resp.status_code == 422

    def test_register_invalid_username_pattern(self, client) -> None:
        """Username avec espaces → 422."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "user name",
                "password": "secure-password-123",
            },
        )
        assert resp.status_code == 422

    def test_register_short_username(self, client) -> None:
        """Username trop court (< 3) → 422."""
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "ab",
                "password": "secure-password-123",
            },
        )
        assert resp.status_code == 422
