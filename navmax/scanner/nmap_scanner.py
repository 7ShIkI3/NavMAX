"""
NmapScanner — wrapper asynchrone autour de python-nmap avec fallback scapy.

Détection OS, version detection, NSE scripts, avec fallback élégant
vers le scanner TCP natif (scapy) si nmap n'est pas installé.
"""

import asyncio
import shutil
import structlog
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class NmapHostResult:
    """Résultat d'un scan nmap pour un hôte."""
    host: str
    status: str = "down"  # "up" or "down"
    ports: dict[int, dict] = field(default_factory=dict)
    os_matches: list[dict] = field(default_factory=list)
    os_cpe: str = ""
    uptime: Optional[str] = None
    mac_address: Optional[str] = None
    error: Optional[str] = None


@dataclass
class PortScanResult:
    """Résultat enrichi pour un port scanné."""
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    cpe: Optional[str] = None
    script_results: dict = field(default_factory=dict)
    os_detected: Optional[str] = None
    os_accuracy: int = 0
    vulnerabilities: list[dict] = field(default_factory=list)


class NmapScanner:
    """Wrapper asynchrone autour de python-nmap avec fallback scapy.

    Utilise asyncio.to_thread() pour ne pas bloquer la boucle asynchrone.
    Détecte automatiquement si nmap est installé ; sinon, tombe sur un
    scanner TCP natif via asyncio.open_connection (scapy fallback).
    """

    def __init__(self):
        self._nmap_available: Optional[bool] = None
        self._nmap = None  # import nmap (lazy)

    @property
    def available(self) -> bool:
        """Vérifie si nmap est installé sur le système."""
        if self._nmap_available is not None:
            return self._nmap_available
        self._nmap_available = shutil.which("nmap") is not None
        return self._nmap_available

    async def scan(
        self,
        host: str,
        ports: Optional[list[int]] = None,
        args: str = "-sV -O --osscan-guess",
        timeout: int = 120,
        scripts: Optional[list[str]] = None,
    ) -> NmapHostResult:
        """Lance un scan nmap complet sur un hôte.

        Args:
            host: Cible (IP ou hostname)
            ports: Liste de ports (ex: [80, 443, 22]). None = ports communs
            args: Arguments nmap (défaut: -sV -O --osscan-guess)
            timeout: Timeout en secondes
            scripts: Scripts NSE à exécuter (ex: ["vuln", "safe"])

        Returns:
            NmapHostResult avec les résultats structurés
        """
        result = NmapHostResult(host=host)

        if not self.available:
            logger.info("nmap_scanner_fallback", host=host)
            return await self._fallback_scan(host, ports, timeout)

        try:
            import nmap  # type: ignore
        except ImportError:
            logger.info("nmap_python_missing_fallback", host=host)
            return await self._fallback_scan(host, ports, timeout)

        # Construire la chaîne de ports
        port_str = ""
        if ports:
            port_str = ",".join(str(p) for p in ports)

        # Ajouter les scripts NSE
        nse_args = args
        if scripts:
            script_str = ",".join(scripts)
            nse_args += f" --script={script_str}"

        if port_str:
            nse_args += f" -p {port_str}"

        try:
            nm = nmap.PortScanner()

            def _run():
                nm.scan(hosts=host, arguments=nse_args, timeout=timeout)
                return nm

            nm = await asyncio.to_thread(_run)

            # Traiter les résultats
            if host not in nm.all_hosts():
                # Essayer avec le nom d'hôte brut
                for h in nm.all_hosts():
                    if h == host or h.startswith(host):
                        result.status = nm[h].state()
                        break
                else:
                    result.status = "down"
                    return result

            host_data = nm[host]
            result.status = host_data.state()

            # OS Detection
            if "osmatch" in host_data and host_data["osmatch"]:
                for osm in host_data["osmatch"]:
                    match = {
                        "name": osm.get("name", ""),
                        "accuracy": osm.get("accuracy", 0),
                        "line": osm.get("line", ""),
                        "osclass": osm.get("osclass", []),
                    }
                    result.os_matches.append(match)

                # Meilleur match
                best = host_data["osmatch"][0]
                result.os_cpe = best.get("osclass", [{}])[0].get("cpe", "") if best.get("osclass") else ""

            # Uptime
            if "uptime" in host_data:
                result.uptime = host_data["uptime"].get("seconds", "")

            # Ports
            if "tcp" in host_data:
                for port, pdata in host_data["tcp"].items():
                    entry = PortScanResult(
                        port=port,
                        protocol="tcp",
                        state=pdata.get("state", "closed"),
                        service=pdata.get("name", ""),
                        product=pdata.get("product", ""),
                        version=pdata.get("version", ""),
                        extrainfo=pdata.get("extrainfo", ""),
                        cpe=pdata.get("cpe", ""),
                    )
                    # Script results
                    if "script" in pdata:
                        entry.script_results = dict(pdata["script"])

                    result.ports[port] = entry.__dict__

            # MAC address
            if "addresses" in host_data:
                if "mac" in host_data["addresses"]:
                    result.mac_address = host_data["addresses"]["mac"]

        except Exception as e:
            logger.error("nmap_scan_error", host=host, error=str(e))
            result.error = str(e)

        return result

    async def scan_os(self, host: str, timeout: int = 120) -> NmapHostResult:
        """Scan spécifique pour la détection OS (nmap -O)."""
        return await self.scan(host, args="-O --osscan-guess", timeout=timeout)

    async def scan_services(
        self,
        host: str,
        ports: Optional[list[int]] = None,
        timeout: int = 120,
    ) -> NmapHostResult:
        """Scan spécifique pour la détection de services/versions (nmap -sV)."""
        return await self.scan(host, ports=ports, args="-sV", timeout=timeout)

    async def scan_vuln(
        self,
        host: str,
        ports: Optional[list[int]] = None,
        timeout: int = 300,
    ) -> NmapHostResult:
        """Scan avec scripts NSE de vulnérabilité (--script vuln)."""
        return await self.scan(
            host, ports=ports,
            args="-sV --script=vuln --script-args=unsafe=1",
            timeout=timeout,
        )

    async def scan_nse(
        self,
        host: str,
        scripts: list[str],
        ports: Optional[list[int]] = None,
        timeout: int = 180,
    ) -> NmapHostResult:
        """Scan avec scripts NSE personnalisés."""
        return await self.scan(
            host, ports=ports,
            args="-sV",
            scripts=scripts,
            timeout=timeout,
        )

    # ── Fallback Scapy / asyncio ──────────────────────────────

    async def _fallback_scan(
        self,
        host: str,
        ports: Optional[list[int]],
        timeout: int,
    ) -> NmapHostResult:
        """Fallback quand nmap n'est pas disponible.

        Utilise asyncio.open_connection pour un TCP Connect scan basique,
        et tente de faire du banner grabbing pour l'identification.
        """
        result = NmapHostResult(host=host, status="up")

        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389,
                     5432, 6379, 8080, 8443, 9200, 27017]

        async def check_port(port: int):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=min(timeout, 5))
                # Banner grab
                w.write(b"\r\n")
                await w.drain()
                banner = b""
                try:
                    banner = await asyncio.wait_for(r.read(1024), timeout=2)
                except asyncio.TimeoutError:
                    pass
                w.close()
                return port, {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "banner": banner.decode("utf-8", errors="replace").strip(),
                    "service": self._guess_service(port, banner.decode("utf-8", errors="replace")),
                }
            except Exception:
                return port, None

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)

        for port, data in results:
            if data:
                result.ports[port] = data

        return result

    def _guess_service(self, port: int, banner: str) -> str:
        """Identifie le service à partir du port et du banner."""
        b = banner.lower()
        if b.startswith("ssh-") or "openssh" in b:
            return "ssh"
        if any(s in b for s in ["http/", "html", "apache", "nginx", "iis"]):
            return "http"
        if "mysql" in b or "mariadb" in b:
            return "mysql"
        if "postgresql" in b:
            return "postgresql"
        if "-err" in b or "+pong" in b or "redis" in b:
            return "redis"
        if "mongodb" in b:
            return "mongodb"
        if b.startswith("220") and "ftp" in b:
            return "ftp"
        if "smb" in b.lower() or "samba" in b.lower():
            return "smb"
        # Fallback port-based
        port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            6379: "redis", 8080: "http", 8443: "https",
            9200: "elasticsearch", 27017: "mongodb",
        }
        return port_map.get(port, "unknown")


# ── Helper pour enrichir ContextualScanResult ────────────────

async def enrich_with_nmap(
    host: str,
    ports: list[int],
    nmap_scanner: Optional[NmapScanner] = None,
) -> dict:
    """Enrichit un résultat de scan avec les données nmap.

    Args:
        host: Hôte cible
        ports: Liste des ports ouverts
        nmap_scanner: Instance NmapScanner (créée si None)

    Returns:
        Dict avec OS, versions détaillées, scripts NSE
    """
    scanner = nmap_scanner or NmapScanner()
    result = await scanner.scan(host, ports=ports)
    return {
        "os_matches": result.os_matches,
        "os_cpe": result.os_cpe,
        "ports": result.ports,
        "mac_address": result.mac_address,
        "scanner_used": "nmap" if scanner.available else "fallback",
    }
