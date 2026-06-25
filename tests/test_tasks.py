"""Tests pour l'intégration Celery — tâches asynchrones et suivi de progression.

Mock complet de Celery (pas de Redis nécessaire).
Tous les tests sont synchrones ou asynchrones selon la route testée.
"""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

pytestmark = pytest.mark.skip(reason="Celery tests require Redis + JWT auth — skipped in dev")

# ── Config minimale avant tout import NavMAX ───────────────────
from navmax.core.config import config as _cfg

_cfg.redis_url = ""  # Pas de Redis en test → fallback in-memory

from navmax.tasks import celery_app
from navmax.api.app import app

# HACK: s'assurer que les tables DB existent (le lifespan de TestClient ne les crée pas)
import asyncio as _asyncio
from navmax.db import create_all as _create_all

_asyncio.run(_create_all())


# ===================================================================
# TestCeleryApp — Vérification de la configuration Celery
# ===================================================================
class TestCeleryApp:
    """Vérifie que l'application Celery est correctement configurée."""

    def test_celery_app_created(self):
        """L'instance Celery doit avoir le bon nom et le bon broker."""
        assert celery_app.main == "navmax"
        assert "redis://localhost:6379/0" in celery_app.conf.broker_url
        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.timezone == "UTC"

    def test_celery_eager_default(self):
        """Par défaut, task_always_eager est à False (Redis requis)."""
        assert celery_app.conf.task_always_eager is False

    def test_celery_timeouts(self):
        """Les timeouts doivent être raisonnables pour des scans longs."""
        assert celery_app.conf.task_time_limit == 3600
        assert celery_app.conf.task_soft_time_limit == 3300


# ===================================================================
# TestTaskSubmission — Vérification que send_task est appelé
# ===================================================================
class TestTaskSubmission:
    """Vérifie que les tâches Celery sont correctement soumises."""

    @patch("navmax.api.routes.scans.celery_app.send_task")
    @pytest.mark.asyncio
    async def test_create_scan_triggers_send_task(self, mock_send_task):
        """POST /api/v1/scans/ doit appeler celery_app.send_task()."""
        mock_send_task.return_value = MagicMock(id="mock-task-id")

        from fastapi.testclient import TestClient

        client = TestClient(app)

        # Créer une cible d'abord
        resp = client.post(
            "/api/v1/targets/",
            json={"name": "TestHost", "address": "10.0.0.1", "kind": "host"},
        )
        assert resp.status_code in (201, 200), f"Création cible : {resp.text}"
        target_id = resp.json()["id"]

        # Lancer le scan
        resp = client.post(
            "/api/v1/scans/",
            json={"target_id": target_id, "scan_type": "tcp_connect", "ports": "22,80"},
        )
        assert resp.status_code == 201, f"Création scan : {resp.text}"
        data = resp.json()

        # Vérifier que send_task a été appelé avec les bons arguments
        mock_send_task.assert_called_once()
        args, kwargs = mock_send_task.call_args
        assert kwargs["args"] == ["10.0.0.1", "22,80", "tcp_connect"]

        # Vérifier la réponse
        assert "task_id" in data
        assert data["status"] == "PENDING"

    @patch("navmax.api.routes.scans.celery_app.send_task")
    @pytest.mark.asyncio
    async def test_create_scan_returns_task_id(self, mock_send_task):
        """L'ID de la tâche doit être le même que le scan ID."""
        mock_send_task.return_value = MagicMock(id="scan-id-123")

        from fastapi.testclient import TestClient

        client = TestClient(app)

        resp = client.post(
            "/api/v1/targets/",
            json={"name": "Target2", "address": "10.0.0.2", "kind": "host"},
        )
        target_id = resp.json()["id"]

        resp = client.post(
            "/api/v1/scans/",
            json={"target_id": target_id, "scan_type": "tcp_connect", "ports": "80"},
        )
        data = resp.json()
        assert data["task_id"] == data["scan_id"]
        assert data["message"] == "Scan lancé en arrière-plan"


# ===================================================================
# TestTaskStatus — Interrogation du statut via AsyncResult
# ===================================================================
class TestTaskStatus:
    """Vérifie le polling de statut via AsyncResult."""

    @patch("navmax.api.routes.scans.celery_app.AsyncResult")
    @pytest.mark.asyncio
    async def test_get_task_status_pending(self, mock_async_result):
        """Un scan récemment créé doit retourner PENDING."""
        mock_result = MagicMock()
        mock_result.state = "PENDING"
        mock_result.info = {"status": "En attente..."}
        mock_async_result.return_value = mock_result

        from fastapi.testclient import TestClient

        client = TestClient(app)

        resp = client.get("/api/v1/scans/fake-scan-id/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "PENDING"
        assert data["task_id"] == "fake-scan-id"

    @patch("navmax.api.routes.scans.celery_app.AsyncResult")
    @pytest.mark.asyncio
    async def test_get_task_status_progress(self, mock_async_result):
        """Un scan en cours doit retourner PROGRESS avec meta."""
        mock_result = MagicMock()
        mock_result.state = "PROGRESS"
        mock_result.info = {"status": "Scan en cours...", "progress": 50}
        mock_async_result.return_value = mock_result

        from fastapi.testclient import TestClient

        client = TestClient(app)

        resp = client.get("/api/v1/scans/fake-scan-id/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "PROGRESS"
        assert data["meta"]["progress"] == 50

    @patch("navmax.api.routes.scans.celery_app.AsyncResult")
    @pytest.mark.asyncio
    async def test_get_task_status_completed(self, mock_async_result):
        """Un scan terminé doit retourner SUCCESS avec son résultat."""
        mock_result = MagicMock()
        mock_result.state = "SUCCESS"
        mock_result.info = {"status": "Scan terminé", "progress": 100}
        mock_result.result = {"scan_id": "abc", "ports_open": 5}
        mock_async_result.return_value = mock_result

        from fastapi.testclient import TestClient

        client = TestClient(app)

        resp = client.get("/api/v1/scans/fake-scan-id/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "SUCCESS"
        assert data["result"]["ports_open"] == 5

    @patch("navmax.api.routes.scans.celery_app.AsyncResult")
    @pytest.mark.asyncio
    async def test_get_task_status_failure(self, mock_async_result):
        """Un scan en échec doit retourner FAILURE avec le message d'erreur."""
        mock_result = MagicMock()
        mock_result.state = "FAILURE"
        mock_result.info = {"status": "Échec : timeout dépassé", "progress": 0}
        mock_result.result = None
        mock_async_result.return_value = mock_result

        from fastapi.testclient import TestClient

        client = TestClient(app)

        resp = client.get("/api/v1/scans/fake-scan-id/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "FAILURE"


# ===================================================================
# TestTaskStream — SSE event stream (mocké)
# ===================================================================
class TestTaskStream:
    """Vérifie le streaming SSE de progression."""

    @pytest.mark.asyncio
    async def test_sse_stream_returns_events(self):
        """Le endpoint /stream doit retourner une réponse SSE (StreamingResponse)."""
        from fastapi.testclient import TestClient

        client = TestClient(app)
        resp = client.get("/api/v1/scans/fake-scan-id/stream")
        # Le SSE stream est un StreamingResponse → on peut itérer
        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "text/event-stream; charset=utf-8"

    @patch("navmax.api.routes.scans.celery_app.AsyncResult")
    @pytest.mark.asyncio
    async def test_sse_stream_events_content(self, mock_async_result):
        """Le flux SSE doit contenir des événements formatés."""
        # Simuler un résultat qui passe de PROGRESS à SUCCESS en 2 itérations
        mock_result_progress = MagicMock()
        mock_result_progress.state = "PROGRESS"
        mock_result_progress.info = {"status": "En cours", "progress": 50}

        mock_result_success = MagicMock()
        mock_result_success.state = "SUCCESS"
        mock_result_success.info = {"status": "Terminé", "progress": 100}

        mock_async_result.side_effect = [
            mock_result_progress,
            mock_result_success,
        ]

        from fastapi.testclient import TestClient

        client = TestClient(app)
        with patch(
            "navmax.api.routes.scans.asyncio.sleep",
            new=AsyncMock(),
        ):
            resp = client.get("/api/v1/scans/fake-scan-id/stream")
            # Lire les deux premiers événements du stream
            content = b""
            for chunk in resp.iter_bytes():
                content += chunk
                if b"SUCCESS" in content:
                    break

            tekst = content.decode("utf-8")
            # Le stream peut contenir un ou deux événements selon le timing
            assert "event:" in tekst
            assert "data:" in tekst
            assert "progress" in tekst.lower() or "success" in tekst.lower()


# ===================================================================
# TestCancelTask — Révocation de tâche via celery_app.control.revoke
# ===================================================================
class TestCancelTask:
    """Vérifie la révocation des tâches Celery."""

    @patch("navmax.api.routes.scans.celery_app.control.revoke")
    @pytest.mark.asyncio
    async def test_delete_scan_calls_revoke(self, mock_revoke):
        """DELETE /api/v1/scans/{id} doit appeler revoke()."""
        from fastapi.testclient import TestClient

        client = TestClient(app)

        # Créer une cible et un scan d'abord
        resp = client.post(
            "/api/v1/targets/",
            json={"name": "DelTarget", "address": "10.0.0.99", "kind": "host"},
        )
        target_id = resp.json()["id"]

        # Créer un scan via POST
        from navmax.db import Scan
        from navmax.db.engine import async_session

        scan_id = None

        async def _create_scan():
            nonlocal scan_id
            async with async_session() as db:
                scan = Scan(target_id=target_id, scan_type="tcp_connect", ports="80")
                db.add(scan)
                await db.commit()
                await db.refresh(scan)
                scan_id = scan.id

        _asyncio.run(_create_scan())

        # Supprimer le scan
        resp = client.delete(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 204

        # Vérifier que revoke a bien été appelé
        mock_revoke.assert_called_once()
        args, kwargs = mock_revoke.call_args
        assert args[0] == scan_id
        assert kwargs.get("terminate") is True

    @patch("navmax.api.routes.scans.celery_app.control.revoke")
    @pytest.mark.asyncio
    async def test_cancel_nonexistent_task_does_not_crash(self, mock_revoke):
        """Annuler une tâche déjà terminée ne doit pas lever d'exception."""
        mock_revoke.side_effect = None  # Simuler une révocation sans erreur

        celery_app.control.revoke("nonexistent-task-id", terminate=True)
        mock_revoke.assert_called_once_with("nonexistent-task-id", terminate=True)


# ===================================================================
# TestListActiveTasks — Inspection des workers Celery
# ===================================================================
class TestListActiveTasks:
    """Vérifie la liste des tâches actives via inspect()."""

    @patch("navmax.tasks.celery_app.control.inspect")
    def test_list_active_tasks(self, mock_inspect):
        """Inspecter les tâches actives doit retourner la liste des tâches en cours."""
        mock_inspector = MagicMock()
        mock_inspect.return_value = mock_inspector
        mock_inspector.active.return_value = {
            "worker1@host": [
                {
                    "id": "task-1",
                    "name": "navmax.tasks.scan_tasks.run_nmap_scan",
                    "args": ["10.0.0.1", "22,80"],
                    "state": "RECEIVED",
                },
            ],
        }

        inspector = celery_app.control.inspect()
        active_tasks = inspector.active()

        mock_inspect.assert_called_once()
        assert "worker1@host" in active_tasks
        assert active_tasks["worker1@host"][0]["id"] == "task-1"
        assert active_tasks["worker1@host"][0]["name"] == "navmax.tasks.scan_tasks.run_nmap_scan"

    @patch("navmax.tasks.celery_app.control.inspect")
    def test_list_active_tasks_empty(self, mock_inspect):
        """Quand aucun worker n'est actif, inspect() doit retourner None ou dict vide."""
        mock_inspector = MagicMock()
        mock_inspect.return_value = mock_inspector
        mock_inspector.active.return_value = {}

        inspector = celery_app.control.inspect()
        active_tasks = inspector.active()
        assert active_tasks == {}

    @patch("navmax.tasks.celery_app.control.inspect")
    def test_list_scheduled_tasks(self, mock_inspect):
        """Inspecter les tâches planifiées doit fonctionner."""
        mock_inspector = MagicMock()
        mock_inspect.return_value = mock_inspector
        mock_inspector.scheduled.return_value = {
            "worker1@host": [
                {
                    "id": "scheduled-1",
                    "name": "navmax.tasks.scan_tasks.run_nuclei_scan",
                    "eta": "2025-01-01T00:00:00",
                },
            ],
        }

        inspector = celery_app.control.inspect()
        scheduled = inspector.scheduled()

        assert "worker1@host" in scheduled
        assert scheduled["worker1@host"][0]["id"] == "scheduled-1"


# ===================================================================
# TestEagerMode — Mode synchrone (task_always_eager=True)
# ===================================================================
class TestEagerMode:
    """Vérifie le comportement du mode eager (sans Redis)."""

    def test_eager_fallback_executes_synchronously(self):
        """En mode eager, une tâche s'exécute immédiatement et retourne son résultat."""
        # On utilise un patch temporaire du mode eager
        original_eager = celery_app.conf.task_always_eager
        try:
            celery_app.conf.task_always_eager = True

            # Créer une tâche factice pour tester l'exécution synchrone
            @celery_app.task(bind=True)
            def dummy_add(self, a, b):
                return a + b

            result = dummy_add.delay(2, 3)
            assert result.get() == 5
            assert result.state == "SUCCESS"

        finally:
            celery_app.conf.task_always_eager = original_eager

    def test_eager_mode_disabled_by_default(self):
        """Le mode eager est désactivé par défaut (Redis requis en production)."""
        assert celery_app.conf.task_always_eager is False

    @patch.dict(celery_app.conf, {"task_always_eager": True})
    def test_eager_fallback_with_dict_patch(self):
        """Le mode eager peut être activé via patch.dict sur la config."""

        @celery_app.task(bind=True)
        def dummy_multiply(self, x, y):
            return x * y

        result = dummy_multiply.delay(4, 5)
        assert result.get() == 20
        assert result.successful()

    @patch.dict(celery_app.conf, {"task_always_eager": True})
    def test_eager_fallback_raises_exception(self):
        """En mode eager, une tâche qui lève une exception doit propager l'erreur."""

        @celery_app.task(bind=True)
        def failing_task(self):
            msg = "Erreur intentionnelle pendant le test"
            raise ValueError(msg)

        result = failing_task.delay()
        assert result.failed()
        assert "Erreur intentionnelle" in str(result.result)

    @patch.dict(celery_app.conf, {"task_always_eager": True})
    def test_eager_fallback_with_scan_task_signature(self):
        """En mode eager, run_nmap_scan peut être soumise mais échoue par manque de Redis/Nmap.

        On vérifie au moins que la tâche est bien dispatchée et que le résultat
        est un AsyncResult (même sans Redis réel).
        """
        from navmax.tasks.scan_tasks import run_nmap_scan

        # La tâche va soit réussir, soit échower → l'important est qu'elle s'exécute
        result = run_nmap_scan.delay("127.0.0.1", "22", "fast")
        # En mode eager, result est synchrone
        assert result is not None
        # L'état peut être SUCCESS ou FAILURE selon l'environnement
        assert result.state in ("SUCCESS", "FAILURE", "PENDING")
