"""
Agent SDK — Client Python asynchrone pour l'API NavMAX.

Usage :
    from navmax.sdk import NavMAXClient

    async with NavMAXClient() as client:
        target = await client.create_target("Serveur Web", "192.168.1.10")
        scan = await client.scan(target["id"])
        print(scan["result_summary"])
"""

from typing import Any

import httpx

from navmax.core.config import config
from navmax.core.logging import get_logger

logger = get_logger(__name__)


class NavMAXError(Exception):
    """Erreur retournée par l'API NavMAX."""


class NavMAXClient:
    """
    Client asynchrone pour l'API REST NavMAX.
    Utilisable par des agents IA pour piloter la plateforme.
    """

    def __init__(self, base_url: str | None = None, timeout: float = 30.0) -> None:
        self.base_url = (base_url or f"http://{config.api_host}:{config.api_port}").rstrip("/")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "NavMAXClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout),
            headers={"User-Agent": "NavMAX-SDK/0.1"},
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise NavMAXError("Client non initialisé — utiliser 'async with NavMAXClient() as client:'")
        return self._client

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    async def health(self) -> dict:
        """Vérifie que l'API NavMAX est accessible."""
        r = await self.client.get("/api/v1/health")
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------
    async def create_target(
        self,
        name: str,
        address: str,
        kind: str = "host",
        tags: str | None = None,
        notes: str | None = None,
    ) -> dict:
        """Crée une nouvelle cible."""
        r = await self.client.post("/api/v1/targets/", json={
            "name": name,
            "address": address,
            "kind": kind,
            "tags": tags,
            "notes": notes,
        })
        self._check(r)
        return r.json()

    async def list_targets(
        self,
        kind: str | None = None,
        alive: bool | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict:
        """Liste les cibles."""
        params: dict = {"offset": offset, "limit": limit}
        if kind:
            params["kind"] = kind
        if alive is not None:
            params["alive"] = str(alive).lower()
        r = await self.client.get("/api/v1/targets/", params=params)
        self._check(r)
        return r.json()

    async def get_target(self, target_id: str) -> dict:
        """Récupère une cible."""
        r = await self.client.get(f"/api/v1/targets/{target_id}")
        self._check(r)
        return r.json()

    async def update_target(self, target_id: str, **fields: Any) -> dict:
        """Met à jour une cible."""
        r = await self.client.patch(f"/api/v1/targets/{target_id}", json=fields)
        self._check(r)
        return r.json()

    async def delete_target(self, target_id: str) -> None:
        """Supprime une cible."""
        r = await self.client.delete(f"/api/v1/targets/{target_id}")
        self._check(r)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    async def scan(
        self,
        target_id: str,
        scan_type: str = "tcp_connect",
        ports: str | None = None,
        poll_interval: float = 1.0,
        max_wait: float = 120.0,
    ) -> dict:
        """
        Lance un scan et attend sa complétion.

        Args:
            target_id: ID de la cible
            scan_type: tcp_connect | tcp_syn | udp | service_detect | os_detect
            ports: "22,80,443" ou "1-1000" — None pour les ports par défaut
            poll_interval: Intervalle de polling en secondes
            max_wait: Temps max d'attente en secondes

        Returns:
            Le scan complété avec result_summary
        """
        r = await self.client.post("/api/v1/scans/", json={
            "target_id": target_id,
            "scan_type": scan_type,
            "ports": ports,
        })
        self._check(r)
        scan = r.json()
        scan_id = scan["id"]

        import asyncio

        elapsed = 0.0
        while elapsed < max_wait:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            scan = await self.get_scan(scan_id)
            if scan["status"] in ("completed", "failed"):
                return scan

        return scan  # Timeout — retourne l'état actuel

    async def get_scan(self, scan_id: str) -> dict:
        """Récupère un scan."""
        r = await self.client.get(f"/api/v1/scans/{scan_id}")
        self._check(r)
        return r.json()

    async def list_scans(
        self,
        target_id: str | None = None,
        status: str | None = None,
        scan_type: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict:
        """Liste les scans."""
        params: dict = {"offset": offset, "limit": limit}
        if target_id:
            params["target_id"] = target_id
        if status:
            params["status"] = status
        if scan_type:
            params["scan_type"] = scan_type
        r = await self.client.get("/api/v1/scans/", params=params)
        self._check(r)
        return r.json()

    async def delete_scan(self, scan_id: str) -> None:
        """Supprime un scan."""
        r = await self.client.delete(f"/api/v1/scans/{scan_id}")
        self._check(r)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _check(response: httpx.Response) -> None:
        if response.status_code >= 400:
            detail = "Unknown error"
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                pass
            raise NavMAXError(f"[{response.status_code}] {detail}")
