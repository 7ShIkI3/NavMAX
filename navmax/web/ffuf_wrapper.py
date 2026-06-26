"""FFUF Wrapper — fuzzing HTTP ultra-rapide via ffuf.

Utilise le binaire ffuf en ligne de commande avec sortie JSON parsée
pour le fuzzing de répertoires, virtual hosts, paramètres, etc.

Sécurité : les options sont limitées à un ensemble whitelisté.
Aucun passage d'arguments bruts depuis l'utilisateur.

Usage:
    wrapper = FfufWrapper()
    result = await wrapper.dir_bust("http://target.com/FUZZ", "/path/to/wordlist.txt")
    for entry in result.entries:
        print(f"{entry.url} ({entry.status}) [{entry.size}]")
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from ..core.logging import get_logger

logger = get_logger(__name__)


# ── Options whitelistées ffuf ───────────────────────────────────

WHITELISTED_OPTIONS: set[str] = {
    # Filtres
    "fc",
    "fs",
    "fw",
    "fl",
    "ft",
    "fr",
    "mode",
    # Performance
    "t",
    "rate",
    "timeout",
    "max-time",
    "ignore-body",
    # Requête
    "X",
    "H",
    "d",
    "b",
    "recursion",
    "recursion-depth",
    "matcher",
    "filter",
    "u",
    "w",
    "ac",
    "acc",
    "c",
    "v",
}

BOOLEAN_FLAGS: set[str] = {
    "ignore-body",
    "recursion",
    "ac",
    "c",
    "v",
}


class FfufFilterOption(StrEnum):
    """Options de filtre pour ffuf.

    Chaque option correspond à un paramètre -fc, -fs, -fw, -fl, -ft.
    """

    STATUS_CODE = "fc"  # Filtrer par code HTTP (ex: 200, 301, 403)
    SIZE = "fs"  # Filtrer par taille de réponse
    WORDS = "fw"  # Filtrer par nombre de mots
    LINES = "fl"  # Filtrer par nombre de lignes


@dataclass
class FfufEntry:
    """Entrée individuelle d'un résultat ffuf.

    Attributes:
        url: URL complète trouvée.
        status: Code HTTP.
        size: Taille de la réponse (bytes).
        words: Nombre de mots.
        lines: Nombre de lignes.
        content_type: Type de contenu (si disponible).
        duration: Durée de la requête (ms).
    """

    url: str
    status: int = 0
    size: int = 0
    words: int = 0
    lines: int = 0
    content_type: str = ""
    duration: float = 0.0


@dataclass
class FfufInput:
    """Entrée de configuration pour un scan ffuf.

    Attributes:
        url: URL cible avec mot-clé FUZZ.
        wordlist: Chemin vers la wordlist.
        options: Options whitelistées supplémentaires.
        filter_codes: Codes HTTP à filtrer (ex: "200,301").
        filter_sizes: Tailles à filtrer.
        filter_words: Nombres de mots à filtrer.
    """

    url: str
    wordlist: str
    options: dict[str, str | int | bool | None] = field(default_factory=dict)
    filter_codes: str = ""
    filter_sizes: str = ""
    filter_words: str = ""


@dataclass
class FfufResult:
    """Résultat structuré d'un scan ffuf.

    Attributes:
        url: URL cible scannée.
        wordlist: Wordlist utilisée.
        entries: Liste des découvertes.
        total_entries: Nombre d'entrées.
        duration_seconds: Durée du scan.
        command: Commande exécutée (pour débogage).
        error: Message d'erreur si échec.
        raw_output: Sortie brute (JSON).
    """

    url: str
    wordlist: str
    entries: list[FfufEntry] = field(default_factory=list)
    total_entries: int = 0
    duration_seconds: float = 0.0
    command: str = ""
    error: str | None = None
    raw_output: str = ""


class FfufWrapper:
    """Wrapper asynchrone autour de ffuf.

    Vérifie la disponibilité de ffuf, exécute les scans en subprocess,
    et parse la sortie JSON.

    Usage:
        wrapper = FfufWrapper()
        result = await wrapper.dir_bust("http://target.com/FUZZ", "wordlist.txt")
        result = await wrapper.vhost_discovery("http://target.com", "vhosts.txt")
    """

    def __init__(self, ffuf_path: str | None = None) -> None:
        self._ffuf_path = ffuf_path or shutil.which("ffuf") or "ffuf"
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """Vérifie si ffuf est installé."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self._ffuf_path) is not None
        return self._available

    def check_installation(self) -> str:
        """Retourne l'état d'installation de ffuf."""
        if self.available:
            return f"ffuf est installé : {shutil.which(self._ffuf_path)}"
        return (
            "ffuf n'est pas installé.\n"
            "  - Linux/macOS : go install github.com/ffuf/ffuf/v2@latest\n"
            "  - Windows     : scoop install ffuf  (ou depuis GitHub Releases)\n"
            "  - Ou : https://github.com/ffuf/ffuf/releases"
        )

    def _build_args(
        self,
        url: str,
        wordlist: str,
        output_json: str,
        input_obj: FfufInput | None = None,
    ) -> list[str]:
        """Construit la liste d'arguments pour ffuf.

        Args:
            url: URL cible.
            wordlist: Chemin wordlist.
            output_json: Chemin fichier JSON de sortie.
            input_obj: Configuration supplémentaire.

        Returns:
            Liste d'arguments pour subprocess.
        """
        args = [
            self._ffuf_path,
            "-u",
            url,
            "-w",
            wordlist,
            "-o",
            output_json,
            "-of",
            "json",
        ]

        # Ajouter les options depuis l'input
        options = input_obj.options if input_obj else {}

        # Filtres spécifiques
        if input_obj:
            if input_obj.filter_codes:
                args.extend(["-fc", input_obj.filter_codes])
            if input_obj.filter_sizes:
                args.extend(["-fs", input_obj.filter_sizes])
            if input_obj.filter_words:
                args.extend(["-fw", input_obj.filter_words])

        # Options génériques whitelistées
        for key, value in options.items():
            if key not in WHITELISTED_OPTIONS:
                logger.warning("option_ffuf_ignorée", key=key)
                continue
            if value is None or value is False:
                continue
            opt = f"-{key}"
            if key in BOOLEAN_FLAGS and value is True:
                args.append(opt)
            elif not isinstance(value, bool):
                args.extend([opt, str(value)])

        logger.debug("ffuf_args", args=args)
        return args

    async def fuzz(
        self,
        url: str,
        wordlist: str,
        **options: str | int | bool | None,
    ) -> FfufResult:
        """Lance un fuzzing ffuf générique.

        Args:
            url: URL avec mot-clé FUZZ (ex: http://target.com/FUZZ).
            wordlist: Chemin vers la wordlist.
            **options: Options whitelistées.

        Returns:
            FfufResult structuré.
        """
        inp = FfufInput(url=url, wordlist=wordlist, options=options)
        return await self._execute(inp)

    async def dir_bust(
        self,
        url: str,
        wordlist: str,
        **options: str | int | bool | None,
    ) -> FfufResult:
        """Directory busting — découvre les répertoires/fichiers cachés.

        Les codes 200, 204, 301, 302, 307, 401, 403 sont généralement
        intéressants. On filtre le 404 par défaut.

        Args:
            url: URL cible (le mot-clé FUZZ peut être en fin de chemin).
            wordlist: Wordlist de répertoires/fichiers.
            **options: Options supplémentaires.

        Returns:
            FfufResult avec les répertoires trouvés.
        """
        inp = FfufInput(
            url=url,
            wordlist=wordlist,
            options=options,
            filter_codes="404",
        )
        return await self._execute(inp)

    async def vhost_discovery(
        self,
        url: str,
        wordlist: str,
        **options: str | int | bool | None,
    ) -> FfufResult:
        """Virtual host discovery — découvre les sous-domaines/vhosts.

        Utilise l'en-tête Host: FUZZ pour tester des vhosts.

        Args:
            url: URL de base (ex: http://target.com).
            wordlist: Wordlist de noms d'hôtes.
            **options: Options supplémentaires.

        Returns:
            FfufResult avec les vhosts trouvés.
        """
        import platform

        # Construire l'URL avec schéma pour le vhost
        # Si l'URL contient déjà FUZZ, on l'utilise directement
        if "FUZZ" not in url:
            url = url.rstrip("/")
            # Utiliser Host header via -H
            host_header = f"Host: FUZZ.{extract_domain(url)}"
            opts = dict(options)
            opts["H"] = host_header
            # L'URL devient l'URL de base (sans modification)
            inp = FfufInput(
                url=url.rstrip("/") + "/",
                wordlist=wordlist,
                options=opts,
                filter_codes="404",
            )
        else:
            inp = FfufInput(
                url=url,
                wordlist=wordlist,
                options=options,
                filter_codes="404",
            )

        return await self._execute(inp)

    async def _execute(self, input_obj: FfufInput) -> FfufResult:
        """Exécute ffuf et parse le résultat JSON.

        Args:
            input_obj: Configuration du scan.

        Returns:
            FfufResult structuré.
        """
        import asyncio
        import time

        result = FfufResult(
            url=input_obj.url,
            wordlist=input_obj.wordlist,
        )

        if not self.available:
            result.error = "ffuf n'est pas installé"
            return result

        if not os.path.isfile(input_obj.wordlist):
            result.error = f"Wordlist introuvable : {input_obj.wordlist}"
            return result

        # Créer un fichier temporaire pour la sortie JSON
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
        os.close(tmp_fd)

        try:
            args = self._build_args(
                input_obj.url,
                input_obj.wordlist,
                tmp_path,
                input_obj,
            )

            result.command = " ".join(
                str(a) if " " not in str(a) else f"'{a}'" for a in args
            )

            logger.info(
                "ffuf_start",
                url=input_obj.url,
                wordlist=input_obj.wordlist,
            )

            t_start = time.monotonic()

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,
            )

            result.duration_seconds = time.monotonic() - t_start
            result.raw_output = stdout.decode("utf-8", errors="replace")

            # Parser le fichier JSON de sortie
            if os.path.isfile(tmp_path):
                result = self._parse_json_output(result, tmp_path)
            else:
                # Fallback : parser stdout
                result = self._parse_text_output(result, stdout.decode("utf-8", errors="replace"))

        except asyncio.TimeoutError:
            result.error = "ffuf a dépassé le timeout de 600s"
        except FileNotFoundError:
            result.error = f"Binaire ffuf introuvable : {self._ffuf_path}"
        except Exception as exc:
            logger.exception("ffuf_exec_error", error=str(exc))
            result.error = str(exc)
        finally:
            # Nettoyer le fichier temporaire
            try:
                if os.path.isfile(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

        result.total_entries = len(result.entries)
        return result

    def _parse_json_output(self, result: FfufResult, json_path: str) -> FfufResult:
        """Parse le fichier JSON de sortie ffuf.

        Args:
            result: Résultat à compléter.
            json_path: Chemin vers le fichier JSON.

        Returns:
            FfufResult complet.
        """
        try:
            with open(json_path, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            result.error = f"Erreur parsing JSON ffuf : {exc}"
            return result

        results_list = data.get("results", [])
        for entry in results_list:
            ffuf_entry = FfufEntry(
                url=entry.get("url", ""),
                status=entry.get("status", 0),
                size=entry.get("length", 0),
                words=entry.get("words", 0),
                lines=entry.get("lines", 0),
                content_type=entry.get("content_type", ""),
                duration=entry.get("duration", 0.0),
            )
            result.entries.append(ffuf_entry)

        return result

    def _parse_text_output(self, result: FfufResult, text: str) -> FfufResult:
        """Parse la sortie texte de ffuf (fallback si pas de JSON).

        Formats supportés :
          [Status: 200, Size: 1234, Words: 100, Lines: 20] -> http://test.com/admin
          200     1234     100     20     http://test.com/admin

        Args:
            result: Résultat à compléter.
            text: Sortie texte.

        Returns:
            FfufResult avec entrées parsées.
        """
        # Format 1: [Status: 200, Size: 1234, Words: 100, Lines: 20] -> URL
        pattern1 = re.compile(
            r"\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)\]\s*->\s*(\S+)",
        )
        for match in pattern1.finditer(text):
            ffuf_entry = FfufEntry(
                url=match.group(5),
                status=int(match.group(1)),
                size=int(match.group(2)),
                words=int(match.group(3)),
                lines=int(match.group(4)),
            )
            result.entries.append(ffuf_entry)

        # Format 2: STATUS  SIZE  WORDS  LINES  URL
        if not result.entries:
            pattern2 = re.compile(
                r"(\d{3})\s+(\d+)\w?\s+(\d+)\w?\s+(\d+)\w?\s+(https?://\S+)",
            )
            for match in pattern2.finditer(text):
                ffuf_entry = FfufEntry(
                    url=match.group(5),
                    status=int(match.group(1)),
                    size=int(match.group(2)),
                    words=int(match.group(3)),
                    lines=int(match.group(4)),
                )
                result.entries.append(ffuf_entry)

        return result


def extract_domain(url: str) -> str:
    """Extrait le nom de domaine enregistrable (sans sous-domaine) d'une URL.

    Pour vhost_discovery : on veut le domaine principal pour tester
    des sous-domaines (ex: admin.target.com → target.com).

    Args:
        url: URL complète.

    Returns:
        Domaine principal (ex: target.com).
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    parts = hostname.split(".")

    # Si c'est une adresse IP, retourner telle quelle
    if all(p.replace(".", "").isdigit() for p in parts if p):
        return hostname

    # TLDs composés (2 parties) — on garde 3 parties minimum
    compound_tlds = {
        "co.uk", "com.au", "co.jp", "co.nz", "co.za",
        "org.uk", "ac.uk", "gov.uk", "net.au",
        "com.br", "org.br", "net.br",
        "com.cn", "org.cn", "net.cn",
        "co.in", "net.in", "org.in",
    }

    if len(parts) >= 3:
        last_two = ".".join(parts[-2:]).lower()
        if last_two in compound_tlds:
            # Pour co.uk, garder example.co.uk (3 parties)
            if len(parts) >= 3:
                return ".".join(parts[-3:])
        else:
            # Pour target.com, garder target.com (2 parties)
            return ".".join(parts[-2:])

    return hostname
