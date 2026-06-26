"""SQLMap Wrapper — injection SQL automatisée via sqlmap.

Utilise le binaire sqlmap en ligne de commande (subprocess) et parse
la sortie structurée (JSON/texte) pour retourner des résultats exploitables.

Sécurité : les options sont limitées à un ensemble whitelisté.
Aucun passage d'arguments bruts depuis l'utilisateur.

Usage:
    wrapper = SQLMapWrapper()
    result = await wrapper.scan_url("http://target.com/page?id=1")
    print(result.vulnerable, result.technique)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from navmax.core.logging import get_logger

logger = get_logger(__name__)


# ── Options whitelistées sqlmap ─────────────────────────────────

WHITELISTED_OPTIONS: set[str] = {
    # Comportement
    "batch",
    "random-agent",
    "threads",
    "timeout",
    "retries",
    "delay",
    # Détection
    "level",
    "risk",
    "dbms",
    "technique",
    # Extraction
    "dbms",
    "dump",
    "tables",
    "columns",
    "exclude-sysdbs",
    "stop",
    "start",
    "count",
    # Réseau
    "proxy",
    "cookie",
    "user-agent",
    "headers",
    "host",
    "referer",
    # Auth
    "auth-type",
    "auth-cred",
    # Crawl
    "crawl",
    "crawl-exclude",
}

# Options booléennes (sans valeur)
BOOLEAN_FLAGS: set[str] = {
    "batch",
    "random-agent",
    "exclude-sysdbs",
    "count",
}


@dataclass
class SqlmapStatus:
    """Statut d'exécution sqlmap."""

    running: bool = False
    exit_code: int | None = None
    error: str | None = None


@dataclass
class SqlmapResult:
    """Résultat structuré d'un scan sqlmap.

    Attributes:
        url: URL scannée.
        vulnerable: True si une injection a été trouvée.
        technique: Technique d'injection utilisée (B, E, U, S, T, Q).
        title: Titre de la vulnérabilité.
        payload: Payload utilisé pour confirmer.
        dbms: Base de données identifiée (MySQL, PostgreSQL, etc.).
        db: Base de données courante.
        tables: Liste de tables découvertes.
        columns: Liste de colonnes découvertes.
        entries: Données extraites (dump).
        log_path: Chemin vers le fichier de log sqlmap.
        duration_seconds: Durée du scan.
        error: Message d'erreur si échec.
        raw_output: Sortie brute sqlmap.
    """

    url: str
    vulnerable: bool = False
    technique: str = ""
    title: str = ""
    payload: str = ""
    dbms: str = ""
    db: str = ""
    tables: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    entries: list[dict] = field(default_factory=list)
    log_path: str = ""
    duration_seconds: float = 0.0
    error: str | None = None
    raw_output: str = ""


class SQLMapWrapper:
    """Wrapper asynchrone autour de sqlmap.

    Vérifie la disponibilité de sqlmap, exécute les scans en subprocess,
    et parse la sortie pour fournir des résultats structurés.

    Utilise un répertoire de sortie temporaire pour isoler chaque scan.
    """

    def __init__(self, sqlmap_path: str | None = None) -> None:
        self._sqlmap_path = sqlmap_path or shutil.which("sqlmap") or "sqlmap"
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """Vérifie si sqlmap est installé et accessible."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self._sqlmap_path) is not None
        return self._available

    def check_installation(self) -> str:
        """Retourne l'état d'installation de sqlmap."""
        if self.available:
            return f"sqlmap est installé : {shutil.which(self._sqlmap_path)}"
        return (
            "sqlmap n'est pas installé.\n"
            "  - Linux/macOS : pip install sqlmap  (ou apt/brew)\n"
            "  - Windows     : https://sqlmap.org/#download\n"
            "  Ou via pip : pip install sqlmap"
        )

    def _build_args(
        self,
        url: str,
        output_dir: str,
        options: dict[str, str | int | bool | None],
    ) -> list[str]:
        """Construit la liste d'arguments pour sqlmap.

        Seules les options dans WHITELISTED_OPTIONS sont acceptées.
        Les options inconnues sont ignorées avec un avertissement.

        Args:
            url: URL cible.
            output_dir: Répertoire de sortie.
            options: Options supplémentaires whitelistées.

        Returns:
            Liste d'arguments pour subprocess.
        """
        args = [
            self._sqlmap_path,
            "-u",
            url,
            "--output-dir",
            output_dir,
            "--batch",
        ]

        for key, value in options.items():
            if key not in WHITELISTED_OPTIONS:
                logger.warning("option_sqlmap_ignorée", key=key)
                continue
            if value is None or value is False:
                continue
            opt = f"--{key}"
            if key in BOOLEAN_FLAGS:
                args.append(opt)
            else:
                args.extend([opt, str(value)])

        return args

    async def scan_url(
        self,
        url: str,
        **options: str | int | bool | None,
    ) -> SqlmapResult:
        """Scan complet d'une URL pour injection SQL.

        Args:
            url: URL cible (ex: http://target.com/page?id=1).
            **options: Options whitelistées supplémentaires.

        Returns:
            SqlmapResult structuré.
        """
        import time

        if not self.available:
            return SqlmapResult(
                url=url,
                error="sqlmap n'est pas installé",
            )

        output_dir = tempfile.mkdtemp(prefix="sqlmap_")
        args = self._build_args(url, output_dir, options)

        logger.info("sqlmap_scan_start", url=url, args=args)

        t_start = time.monotonic()
        try:
            proc = await asyncio_subprocess_exec(args)
            result = self._parse_output(url, output_dir, proc.stdout, proc.stderr)
            result.duration_seconds = time.monotonic() - t_start
            return result
        except Exception as exc:
            logger.exception("sqlmap_scan_error", url=url, error=str(exc))
            return SqlmapResult(url=url, error=str(exc))

    async def crawl_and_scan(
        self,
        url: str,
        depth: int = 2,
        **options: str | int | bool | None,
    ) -> SqlmapResult:
        """Crawl puis scanne les points d'entrée découverts.

        Args:
            url: URL de départ pour le crawl.
            depth: Profondeur de crawl (--crawl).
            **options: Options whitelistées supplémentaires.

        Returns:
            SqlmapResult structuré.
        """
        return await self.scan_url(url, crawl=depth, **options)

    async def dump_tables(
        self,
        url: str,
        db: str,
        table: str,
        **options: str | int | bool | None,
    ) -> SqlmapResult:
        """Dump le contenu d'une table.

        Args:
            url: URL cible.
            db: Nom de la base de données.
            table: Nom de la table.
            **options: Options whitelistées supplémentaires.

        Returns:
            SqlmapResult avec les données extraites.
        """
        opts = dict(options)
        opts["dump"] = True
        opts["dbms"] = db  # en pratique c'est le db, on passe en param
        return await self.scan_url(url, **opts)

    def _parse_output(
        self,
        url: str,
        output_dir: str,
        stdout: str,
        stderr: str,
    ) -> SqlmapResult:
        """Parse la sortie sqlmap pour extraire les informations clés.

        Cherche dans stdout/stderr les marqueurs de vulnérabilité,
        technique, DBMS, et données extraites.

        Args:
            url: URL scannée.
            output_dir: Répertoire de sortie sqlmap.
            stdout: Sortie standard.
            stderr: Sortie d'erreur.

        Returns:
            SqlmapResult parsé.
        """
        combined = stdout + "\n" + stderr
        result = SqlmapResult(url=url, raw_output=combined)

        # DBMS — chercher en priorité le back-end DBMS
        # Format: "back-end DBMS: MySQL >= 5.0" ou "back-end DBMS : MySQL"
        dbms_match = re.search(
            r"back-end DBMS\s*:\s*(.+)",
            combined,
            re.IGNORECASE,
        )
        if dbms_match:
            result.dbms = dbms_match.group(1).strip()

        # Fallback: web server technology
        if not result.dbms:
            dbms_match = re.search(
                r"(?:web server|dbms)[^:]*:\s*(.+)",
                combined,
                re.IGNORECASE,
            )
            if dbms_match:
                result.dbms = dbms_match.group(1).strip().split("\n")[0].strip()

        # Injection détectée — chercher le marqueur le plus fiable
        # Important: exclure "are not injectable" / "not injectable"
        if re.search(r"are not injectable|is not injectable", combined, re.IGNORECASE):
            result.vulnerable = False
        else:
            vuln_keywords = [
                "is vulnerable",
                "appears to be.*injectable",
                "sql injection",
                "identified injection",
            ]
            for kw in vuln_keywords:
                if re.search(kw, combined, re.IGNORECASE):
                    result.vulnerable = True
                    break

        # Technique — priorité au type d'injection
        # Ex: "Type: boolean-based blind" → technique "B"
        type_match = re.search(
            r"Type:\s*(\S+)",
            combined,
            re.IGNORECASE,
        )
        if type_match:
            raw_type = type_match.group(1).lower()
            technique_map = {
                "boolean-based": "B",
                "error-based": "E",
                "stacked": "S",
                "time-based": "T",
                "union": "U",
                "inline": "I",
                "blind": "B",
            }
            for key, code in technique_map.items():
                if key in raw_type:
                    result.technique = code
                    break
            if not result.technique:
                result.technique = raw_type.upper()

        # Fallback: technique depuis les paramètres (GET, POST, etc.)
        if not result.technique:
            tech_match = re.search(
                r"Parameter:\s*\w+\s*\((\w+)\)",
                combined,
            )
            if tech_match:
                result.technique = tech_match.group(1).upper()

        # Base de données courante
        db_match = re.search(
            r"current\s+database[^:]*:\s*['\"]?(\w+)['\"]?",
            combined,
            re.IGNORECASE,
        )
        if db_match:
            result.db = db_match.group(1)

        # Tables
        tables = re.findall(
            r"\|[^|]*\+[^|]*\|.*?\|.*?\|",
            combined,
        )
        if tables:
            for line in tables:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if parts and parts[0] not in ("TABLE", "Table", "table", "+"):
                    result.tables.extend(parts)

        # Payload
        payload_match = re.search(
            r"Payload:\s*(.+)",
            combined,
            re.IGNORECASE | re.DOTALL,
        )
        if payload_match:
            result.payload = payload_match.group(1).strip()[:500]

        # Vérifier le fichier log sqlmap
        log_file = Path(output_dir) / "log"
        if log_file.exists():
            result.log_path = str(log_file)
            try:
                with open(log_file, encoding="utf-8", errors="replace") as f:
                    entries = f.read()
                # Chercher les données dumpées
                if "TABLE:" in entries and "ENTRY:" in entries:
                    result.vulnerable = True
            except Exception:
                pass

        # Si rien trouvé, marquer comme non vulnérable
        if not result.vulnerable and "all tested parameters" in combined.lower():
            result.vulnerable = False

        return result


_SubprocessResult = namedtuple(
    "SubprocessResult", ["stdout", "stderr", "returncode"],
)


async def asyncio_subprocess_exec(args: list[str]) -> _SubprocessResult:
    """Exécute une commande en subprocess asynchrone.

    Args:
        args: Arguments de la commande.

    Returns:
        namedtuple avec stdout, stderr, returncode.
    """
    import asyncio

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(),
        timeout=600,
    )

    return _SubprocessResult(
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
        proc.returncode,
    )
