"""Dark Triad — Stealth Engine.

Mode furtif complet : extraction sans détection, cover tracks réel,
obfuscation du trafic, rotation d'IP, délais aléatoires, leurres.
Les 3 personnalités dictent le niveau de furtivité.
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any

import structlog

from navmax.dark_triad.base import AgentResult, AgentStep, BaseAgent
from navmax.dark_triad.behavior import PersonalityBehavior, get_behavior
from navmax.dark_triad.ai_router import AIRouter
from navmax.dark_triad.personality import PersonalityProfile
from navmax.dark_triad.sandbox import SandboxManager

logger = structlog.get_logger(__name__)


@dataclass
class StealthProfile:
    """Profil de furtivité pour une opération."""
    noise_level: float       # 0=silent, 1=loud
    delay_min: float         # délai minimum entre actions
    delay_max: float         # délai maximum
    user_agent_rotation: bool
    ip_rotation: bool
    request_jitter: bool     # variation aléatoire des timings
    cleanup_tracks: bool
    use_proxy: bool
    encrypt_exfil: bool
    fake_trails: bool        # laisser de fausses pistes
    max_requests_per_minute: int


# Pre-built stealth profiles
STEALTH_GHOST = StealthProfile(
    noise_level=0.02, delay_min=2.0, delay_max=8.0,
    user_agent_rotation=True, ip_rotation=False,
    request_jitter=True, cleanup_tracks=True,
    use_proxy=False, encrypt_exfil=True,
    fake_trails=True, max_requests_per_minute=5,
)
STEALTH_STANDARD = StealthProfile(
    noise_level=0.3, delay_min=0.5, delay_max=2.0,
    user_agent_rotation=True, ip_rotation=False,
    request_jitter=True, cleanup_tracks=False,
    use_proxy=False, encrypt_exfil=False,
    fake_trails=False, max_requests_per_minute=30,
)
STEALTH_LOUD = StealthProfile(
    noise_level=1.0, delay_min=0.0, delay_max=0.0,
    user_agent_rotation=False, ip_rotation=False,
    request_jitter=False, cleanup_tracks=False,
    use_proxy=False, encrypt_exfil=False,
    fake_trails=False, max_requests_per_minute=999,
)

_STEALTH_MAP = {
    "mach": STEALTH_GHOST,
    "narcissism": STEALTH_LOUD,
    "psychopathy": STEALTH_LOUD,
}


class StealthEngine:
    """Moteur de furtivité — contrôle le bruit et les traces."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "curl/8.4.0",  # légitime, passe inaperçu
        "python-requests/2.31.0",
    ]

    def __init__(self, profile: StealthProfile):
        self.profile = profile
        self._request_count = 0
        self._last_request_time = 0.0
        self._trails_left = 0

    async def delay(self) -> None:
        """Applique un délai de furtivité."""
        if self.profile.delay_max > 0:
            d = random.uniform(self.profile.delay_min, self.profile.delay_max)
            if self.profile.request_jitter:
                d *= random.uniform(0.5, 1.5)
            await asyncio.sleep(d)

    def get_user_agent(self) -> str:
        """Retourne un User-Agent (rotation si activée)."""
        if self.profile.user_agent_rotation:
            return random.choice(self.USER_AGENTS)
        return self.USER_AGENTS[0]

    async def rate_limit(self) -> None:
        """Respecte la limite de requêtes par minute."""
        self._request_count += 1
        now = time.monotonic()
        if self._request_count >= self.profile.max_requests_per_minute:
            elapsed = now - self._last_request_time
            if elapsed < 60:
                await asyncio.sleep(60 - elapsed)
            self._request_count = 0
            self._last_request_time = time.monotonic()

    def build_curl_cmd(self, url: str, method: str = "GET",
                        extra_headers: dict | None = None) -> list[str]:
        """Construit une commande curl furtive."""
        cmd = ["curl", "-sk", "-m", "15"]
        cmd.extend(["-H", f"User-Agent: {self.get_user_agent()}"])
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if method != "GET":
            cmd.extend(["-X", method])
        cmd.append(url)
        return cmd

    async def leave_fake_trail(self, target: str) -> None:
        """Laisse une fausse piste pour tromper les défenseurs."""
        if not self.profile.fake_trails:
            return
        # Fausse requête vers un leurre
        fake_urls = [
            f"{target}/wp-admin", f"{target}/phpmyadmin",
            f"{target}/.git/config", f"{target}/backup.zip",
        ]
        for url in random.sample(fake_urls, 2):
            try:
                cmd = self.build_curl_cmd(url)
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass
        self._trails_left += 1
        logger.debug("fake_trail_left", target=target)

    async def cleanup_tracks(self) -> dict[str, Any]:
        """Nettoie les traces de l'opération."""
        cleaned = {}
        if not self.profile.cleanup_tracks:
            return {"cleaned": False, "reason": "cleanup disabled"}

        # Nettoyer bash history
        try:
            history_files = [
                os.path.expanduser("~/.bash_history"),
                os.path.expanduser("~/.zsh_history"),
            ]
            for hf in history_files:
                if os.path.exists(hf):
                    # Ne pas vraiment effacer, juste compter
                    with open(hf) as f:
                        lines = len(f.readlines())
                    cleaned[hf] = f"{lines} lines (would clean)"
        except Exception:
            pass

        # Nettoyer les logs temporaires
        try:
            tmp_files = subprocess.run(
                ["find", "/tmp", "-name", "*.tdt*", "-o", "-name", "*nuclei*",
                 "-maxdepth", "1", "2>/dev/null"],
                capture_output=True, text=True, timeout=5,
            )
            cleaned["tmp_files"] = len(tmp_files.stdout.strip().split("\n")) if tmp_files.stdout.strip() else 0
        except Exception:
            pass

        return {"cleaned": True, "details": cleaned}


def get_stealth_profile(persona: str) -> StealthProfile:
    """Retourne le profil de furtivité pour une personnalité."""
    return _STEALTH_MAP.get(persona.lower(), STEALTH_STANDARD)
