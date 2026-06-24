"""
VulnDatabase — base de signatures CVE locale pour matcher service+version → vulnérabilités.

Format: JSON compact avec service, version_range, CVE, sévérité.
Fonctionne 100% offline — pas d'appel API externe.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from packaging.version import Version, InvalidVersion

from navmax.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VulnEntry:
    """Une entrée de vulnérabilité."""
    cve: str
    service: str
    version_range: str  # ex: ">=2.4.49,<2.4.51" ou "*"
    severity: str       # info, low, medium, high, critical
    description: str
    exploit_module: Optional[str] = None  # module NavMAX associé
    references: list[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


# ── Base de signatures intégrée ────────────────────────────────

DEFAULT_SIGNATURES: list[dict] = [
    # Apache HTTPd
    {
        "cve": "CVE-2021-41773",
        "service": "apache",
        "version_range": ">=2.4.49,<2.4.51",
        "severity": "high",
        "description": "Path traversal in Apache HTTP Server 2.4.49-2.4.50",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    {
        "cve": "CVE-2021-42013",
        "service": "apache",
        "version_range": ">=2.4.49,<2.4.51",
        "severity": "critical",
        "description": "Path traversal + RCE in Apache 2.4.49-2.4.50",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
    },
    # OpenSSH
    {
        "cve": "CVE-2024-6387",
        "service": "openssh",
        "version_range": ">=8.5p1,<9.8p1",
        "severity": "high",
        "description": "regreSSHion — RCE in OpenSSH (signal handler race condition)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
    },
    {
        "cve": "CVE-2023-38408",
        "service": "openssh",
        "version_range": "<9.3p2",
        "severity": "critical",
        "description": "RCE via ssh-agent PKCS#11",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    },
    # Redis
    {
        "cve": "CVE-2022-0543",
        "service": "redis",
        "version_range": ">=5.0.0,<=7.0.8",
        "severity": "critical",
        "description": "Lua sandbox escape leading to RCE in Debian/Ubuntu Redis",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
    },
    # MySQL / MariaDB
    {
        "cve": "CVE-2012-2122",
        "service": "mysql",
        "version_range": ">=5.1.0,<5.1.63",
        "severity": "medium",
        "description": "Authentication bypass in MySQL (CAST trick)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
    },
    # PostgreSQL
    {
        "cve": "CVE-2019-9193",
        "service": "postgresql",
        "version_range": ">=9.3,<11.3",
        "severity": "high",
        "description": "COPY FROM PROGRAM — RCE via PostgreSQL",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"],
    },
    # Docker
    {
        "cve": "CVE-2019-5736",
        "service": "docker",
        "version_range": "<18.09.2",
        "severity": "high",
        "description": "Container escape via runc (overwrite host binary)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-5736"],
    },
    # Kubernetes
    {
        "cve": "CVE-2018-1002105",
        "service": "kubernetes",
        "version_range": ">=1.0.0,<1.10.11",
        "severity": "critical",
        "description": "Privilege escalation via Kubernetes API proxy",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"],
    },
    # Elasticsearch
    {
        "cve": "CVE-2015-1427",
        "service": "elasticsearch",
        "version_range": ">=1.0.0,<1.4.0",
        "severity": "high",
        "description": "RCE via Groovy scripting engine",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-1427"],
    },
    # Jenkins
    {
        "cve": "CVE-2024-23897",
        "service": "jenkins",
        "version_range": ">=2.0,<2.442",
        "severity": "high",
        "description": "Arbitrary file read via Jenkins CLI",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
    },
    # Tomcat
    {
        "cve": "CVE-2019-0232",
        "service": "tomcat",
        "version_range": ">=7.0.0,<9.0.20",
        "severity": "high",
        "description": "RCE via CGI Servlet in Windows Tomcat",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0232"],
    },
    # SMB (EternalBlue)
    {
        "cve": "CVE-2017-0144",
        "service": "smb",
        "version_range": "*",
        "severity": "critical",
        "description": "EternalBlue — RCE via SMBv1 (MS17-010)",
        "exploit_module": "eternalblue",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    },
    # Log4Shell
    {
        "cve": "CVE-2021-44228",
        "service": "log4j",
        "version_range": ">=2.0-beta9,<2.15.0",
        "severity": "critical",
        "description": "Log4Shell — RCE via JNDI injection",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    # Nginx
    {
        "cve": "CVE-2019-9513",
        "service": "nginx",
        "version_range": "<1.17.3",
        "severity": "medium",
        "description": "HTTP/2 DoS via resource loop",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-9513"],
    },
    # Exim (mail)
    {
        "cve": "CVE-2019-10149",
        "service": "exim",
        "version_range": ">=4.87,<4.91",
        "severity": "critical",
        "description": "Return of the WIZard — RCE in Exim",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
    },
    # ProFTPd
    {
        "cve": "CVE-2015-3306",
        "service": "proftpd",
        "version_range": ">=1.3.0,<1.3.5",
        "severity": "critical",
        "description": "RCE via mod_copy in ProFTPd",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
    },
    # vsftpd backdoor
    {
        "cve": "CVE-2011-2523",
        "service": "vsftpd",
        "version_range": "==2.3.4",
        "severity": "critical",
        "description": "Backdoor in vsftpd 2.3.4 (smiley face)",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
]


# ── VulnDatabase ────────────────────────────────────────────────

class VulnDatabase:
    """Base de signatures CVE avec matching version.

    Usage:
        db = VulnDatabase()
        vulns = db.check("apache", "2.4.49")
        # → [{"cve": "CVE-2021-41773", ...}, {"cve": "CVE-2021-42013", ...}]
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path(__file__).parent / "data" / "cve_signatures.json"
        self._signatures: list[dict] = []
        self._loaded = False

    def load(self) -> int:
        """Charge les signatures depuis le fichier JSON. Retourne le nombre d'entrées."""
        if self.db_path.exists():
            try:
                with open(self.db_path) as f:
                    self._signatures = json.load(f)
                logger.info("vulndb_loaded", path=str(self.db_path), count=len(self._signatures))
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("vulndb_parse_error", error=str(e))
                self._signatures = DEFAULT_SIGNATURES
        else:
            logger.info("vulndb_default", count=len(DEFAULT_SIGNATURES))
            self._signatures = DEFAULT_SIGNATURES

        self._loaded = True
        return len(self._signatures)

    def check(self, service: str, version: str) -> list[dict]:
        """Vérifie les vulnérabilités pour un service+version.

        Args:
            service: Nom du service (ex: "apache", "openssh", "redis")
            version: Version détectée (ex: "2.4.49", "8.9p1")

        Returns:
            Liste de signatures CVE correspondantes
        """
        if not self._loaded:
            self.load()

        matches = []
        service_low = service.lower()

        for sig in self._signatures:
            if sig["service"].lower() != service_low:
                continue
            if self._version_in_range(version, sig.get("version_range", "*")):
                matches.append(dict(sig))

        return matches

    def check_bulk(self, services: list[dict]) -> dict[str, list[dict]]:
        """Vérifie plusieurs services en une fois.

        Args:
            services: [{"service": "apache", "version": "2.4.49"}, ...]

        Returns:
            {service_key: [vulns]}
        """
        results = {}
        for svc in services:
            key = f"{svc['service']}:{svc.get('port', '?')}"
            vulns = self.check(svc["service"], svc.get("version", ""))
            if vulns:
                results[key] = vulns
        return results

    def _version_in_range(self, version: str, range_spec: str) -> bool:
        """Vérifie si une version est dans un range.

        Formats supportés:
            "*"                          → match tout
            "==2.3.4"                   → exact match
            ">=2.4.49,<2.4.51"          → range
            "<18.09.2"                  → inférieur
            ">=5.0.0,<=7.0.8"          → range inclusif
        """
        if range_spec == "*":
            return True

        if not version:
            return range_spec == "*"

        try:
            v = Version(self._normalize_version(version))
        except InvalidVersion:
            # Fallback: comparaison string
            return self._string_range_match(version, range_spec)

        conditions = [c.strip() for c in range_spec.split(",")]

        for cond in conditions:
            op = ""
            ver_str = cond
            for prefix in [">=", "<=", "==", "!=", ">", "<"]:
                if cond.startswith(prefix):
                    op = prefix
                    ver_str = cond[len(prefix):].strip()
                    break

            try:
                target = Version(self._normalize_version(ver_str))
            except InvalidVersion:
                return False

            if op == ">=" and not (v >= target):
                return False
            elif op == "<=" and not (v <= target):
                return False
            elif op == ">" and not (v > target):
                return False
            elif op == "<" and not (v < target):
                return False
            elif op == "==" and not (v == target):
                return False
            elif op == "!=" and v == target:
                return False

        return True

    def _normalize_version(self, version: str) -> str:
        """Normalise une version pour packaging.version.Version.

        Exemples: "8.5p1" → "8.5.1", "9.3p2" → "9.3.2"
        """
        # OpenSSH style: 8.5p1 → 8.5.1
        v = re.sub(r"p(\d+)", r".\1", version)
        # Strip non-version suffixes
        v = re.sub(r"[^0-9.].*$", "", v)
        # Ensure at least x.y format
        if "." not in v:
            v = f"{v}.0"
        return v

    def _string_range_match(self, version: str, range_spec: str) -> bool:
        """Fallback: comparaison string simple."""
        if range_spec == "*":
            return True
        if range_spec.startswith("=="):
            return version == range_spec[2:].strip()
        return False

    @property
    def count(self) -> int:
        if not self._loaded:
            self.load()
        return len(self._signatures)
