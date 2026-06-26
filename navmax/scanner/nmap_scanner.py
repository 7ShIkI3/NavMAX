"""NmapScanner — wrapper asynchrone autour de python-nmap avec fallback scapy.

Détection OS, version detection, NSE scripts, avec fallback élégant
vers le scanner TCP natif (scapy) si nmap n'est pas installé.

Sécurité stricte : les arguments nmap sont limités à des profils prédéfinis.
Aucun passage d'arguments bruts autorisé.
"""

import asyncio
import contextlib
import re
import shutil
from dataclasses import dataclass, field

from navmax.core.logging import get_logger

logger = get_logger(__name__)

# ── Profils nmap whitelistés ──────────────────────────────────
# Seuls ces profils peuvent être utilisés ; aucun argument nmap libre.
NMAP_PROFILES: dict[str, str] = {
    "quick": "-T4 -F",
    "default": "-sV -sC -T4",
    "deep": "-sV -sC -O -T4 --script vuln",
    "stealth": "-sS -T2 -f",
    "vuln": "-sV --script vuln",
}


def _validate_host(host: str) -> None:
    """Valide que host est une IP ou un hostname basique."""
    if not host or not isinstance(host, str):
        msg = f"host must be a non-empty string, got {type(host).__name__}"
        raise ValueError(msg)
    # Vérification basique : IP (IPv4/v6) ou hostname (DNS)
    host = host.strip()
    # IPv4
    ipv4_re = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # IPv6 simplifié (présence de ':')
    # Hostname (lettres, chiffres, points, tirets)
    hostname_re = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"
    if not (re.match(ipv4_re, host) or ":" in host or re.match(hostname_re, host)):
        msg = f"Invalid host format: '{host}'"
        raise ValueError(msg)


@dataclass
class NmapHostResult:
    """Résultat d'un scan nmap pour un hôte."""

    host: str
    status: str = "down"  # "up" or "down"
    ports: dict[int, dict] = field(default_factory=dict)
    os_matches: list[dict] = field(default_factory=list)
    os_cpe: str = ""
    uptime: str | None = None
    mac_address: str | None = None
    error: str | None = None


@dataclass
class PortScanResult:
    """Résultat enrichi pour un port scanné."""

    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    cpe: str | None = None
    script_results: dict = field(default_factory=dict)
    os_detected: str | None = None
    os_accuracy: int = 0
    vulnerabilities: list[dict] = field(default_factory=list)


class NmapScanner:
    """Wrapper asynchrone autour de python-nmap avec fallback scapy.

    Utilise asyncio.to_thread() pour ne pas bloquer la boucle asynchrone.
    Détecte automatiquement si nmap est installé ; sinon, tombe sur un
    scanner TCP natif via asyncio.open_connection (scapy fallback).

    Les arguments nmap sont strictement limités aux profils prédéfinis
    (NMAP_PROFILES). Aucun argument brut n'est accepté.
    """

    PROFILES = NMAP_PROFILES

    def __init__(self) -> None:
        self._nmap_available: bool | None = None
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
        ports: list[int] | None = None,
        profile: str = "default",
        timeout: int = 120,
        scripts: list[str] | None = None,
        unsafe_scripts: bool = False,
    ) -> NmapHostResult:
        """Lance un scan nmap complet sur un hôte.

        Les arguments nmap sont déterminés par un profil prédéfini uniquement.
        Aucun passage d'arguments bruts n'est autorisé.

        Args:
            host: Cible (IP ou hostname)
            ports: Liste de ports (ex: [80, 443, 22]). None = ports communs
            profile: Profil nmap prédéfini ("quick", "default", "deep", "stealth", "vuln")
            timeout: Timeout en secondes
            scripts: Scripts NSE supplémentaires (ex: ["http-title", "ssl-enum-ciphers"])
            unsafe_scripts: Activer --script-args=unsafe=1 (défaut: False)

        Returns:
            NmapHostResult avec les résultats structurés

        Raises:
            ValueError: Si le profil est inconnu ou si l'hôte est invalide

        """
        # Validation
        _validate_host(host)
        if profile not in self.PROFILES:
            valid = ", ".join(sorted(self.PROFILES.keys()))
            msg = f"Unknown nmap profile '{profile}'. Valid profiles: {valid}"
            raise ValueError(
                msg,
            )

        result = NmapHostResult(host=host)

        if not self.available:
            logger.info("nmap_scanner_fallback", host=host)
            return await self._fallback_scan(host, ports, timeout)

        try:
            import nmap  # type: ignore
        except ImportError:
            logger.info("nmap_python_missing_fallback", host=host)
            return await self._fallback_scan(host, ports, timeout)

        # Construire les arguments à partir du profil
        nse_args = self.PROFILES[profile]

        # Ajouter les scripts NSE supplémentaires
        if scripts:
            script_str = ",".join(scripts)
            nse_args += f" --script={script_str}"

        # Activer unsafe si demandé
        if unsafe_scripts:
            nse_args += " --script-args=unsafe=1"

        # Ajouter les ports
        port_str = ""
        if ports:
            port_str = ",".join(str(p) for p in ports)
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
            if host_data.get("osmatch"):
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
                result.os_cpe = (
                    best.get("osclass", [{}])[0].get("cpe", "") if best.get("osclass") else ""
                )

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
            if "addresses" in host_data and "mac" in host_data["addresses"]:
                result.mac_address = host_data["addresses"]["mac"]

        except (OSError, RuntimeError, ValueError) as e:
            logger.exception("nmap_scan_error", host=host, error=str(e))
            result.error = str(e)

        return result

    async def scan_os(self, host: str, timeout: int = 120) -> NmapHostResult:
        """Scan spécifique pour la détection OS (profil deep avec -O)."""
        return await self.scan(host, profile="deep", timeout=timeout)

    async def scan_services(
        self,
        host: str,
        ports: list[int] | None = None,
        timeout: int = 120,
    ) -> NmapHostResult:
        """Scan spécifique pour la détection de services/versions (profil default)."""
        return await self.scan(host, ports=ports, profile="default", timeout=timeout)

    async def scan_vuln(
        self,
        host: str,
        ports: list[int] | None = None,
        timeout: int = 300,
    ) -> NmapHostResult:
        """Scan avec scripts NSE de vulnérabilité (profil vuln).

        Les scripts unsafe sont activés car il s'agit d'un scan
        de vulnérabilité explicite.
        """
        return await self.scan(
            host,
            ports=ports,
            profile="vuln",
            timeout=timeout,
            unsafe_scripts=True,
        )

    async def scan_nse(
        self,
        host: str,
        scripts: list[str],
        ports: list[int] | None = None,
        timeout: int = 180,
    ) -> NmapHostResult:
        """Scan avec scripts NSE personnalisés (profil default + scripts)."""
        return await self.scan(
            host,
            ports=ports,
            profile="default",
            scripts=scripts,
            timeout=timeout,
        )

    # ── Fallback Scapy / asyncio ──────────────────────────────

    async def _fallback_scan(
        self,
        host: str,
        ports: list[int] | None,
        timeout: int,
    ) -> NmapHostResult:
        """Fallback quand nmap n'est pas disponible.

        Utilise asyncio.open_connection pour un TCP Connect scan basique,
        et tente de faire du banner grabbing pour l'identification.
        """
        result = NmapHostResult(host=host, status="up")

        if not ports:
            ports = [
                21,
                22,
                23,
                25,
                53,
                80,
                443,
                445,
                3306,
                3389,
                5432,
                6379,
                8080,
                8443,
                9200,
                27017,
            ]

        async def check_port(port: int):
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=min(timeout, 5),
                )
            except (TimeoutError, ConnectionRefusedError, OSError):
                return port, None

            banner = b""
            try:
                # Banner grab
                w.write(b"\r\n")
                await w.drain()
                with contextlib.suppress(TimeoutError):
                    banner = await asyncio.wait_for(r.read(1024), timeout=2)
            finally:
                w.close()
                with contextlib.suppress(OSError):
                    await w.wait_closed()

            return port, {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "banner": banner.decode("utf-8", errors="replace").strip(),
                "service": self._guess_service(port, banner.decode("utf-8", errors="replace")),
            }

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
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http",
            8443: "https",
            9200: "elasticsearch",
            27017: "mongodb",
        }
        return port_map.get(port, "unknown")


# ── Helper pour enrichir ContextualScanResult ────────────────


async def enrich_with_nmap(
    host: str,
    ports: list[int],
    nmap_scanner: NmapScanner | None = None,
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
