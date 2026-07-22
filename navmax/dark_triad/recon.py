"""The Dark Triad — Reconnaissance Agent.

Performs passive (OSINT) and active (nmap) reconnaissance with
personality-aware tool selection and scan parameters.
Uses REAL system tools: nmap, dig, curl, openssl.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from dataclasses import dataclass, field

import structlog

from navmax.dark_triad.base import AgentResult, AgentStep, BaseAgent
from navmax.dark_triad.ai_router import AIRouter
from navmax.dark_triad.personality import PersonalityProfile
from navmax.dark_triad.sandbox import SandboxManager
from navmax.dark_triad.tool_registry import ToolCategory, ToolRegistry

logger = structlog.get_logger(__name__)


# ── Shared Dataclass ───────────────────────────────────────────────────────────


@dataclass
class ReconFindings:
    """Aggregated findings from a reconnaissance mission."""

    target: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[str, str] = field(default_factory=dict)
    os_guess: str = "unknown"
    vulnerabilities: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    ssl_info: dict | None = None
    whois: dict | None = None
    notes: list[str] = field(default_factory=list)


class ReconAgent(BaseAgent):
    """Performs multi-phase reconnaissance against a target.

    Personality modes drive scan intensity and stealth:

      NARCISSUS   → aggressive (-T5, all ports, no stealth)
      PSYCHOPATH  → ALL scans in parallel, no rate-limit
      MACHIAVELLI → passive first, slow scan (-T2), rate-limited
    """

    category = "recon"

    _PERSONA_ATTR_MAP = {
        "narcissism": "narcissism",
        "psychopathy": "psychopathy",
        "mach": "machiavellianism",
    }

    @staticmethod
    def _tool_personality(persona: str) -> str:
        return ReconAgent._PERSONA_ATTR_MAP.get(persona, persona)

    def __init__(
        self,
        name: str,
        personality: PersonalityProfile,
        ai_router: AIRouter,
        sandbox: SandboxManager,
    ) -> None:
        super().__init__(name, personality, ai_router, sandbox)

    async def execute(self, objective: str, context: dict | None = None) -> AgentResult:
        start = time.monotonic()
        ctx = context or {}
        steps: list[AgentStep] = []
        step_num = 0
        persona = self.personality.mode.value

        # ── Step 1: Select tools ────────────────────────────────────────
        step_num += 1
        s1 = AgentStep(step_number=step_num, action="select_tools")
        steps.append(s1)
        try:
            tools = ToolRegistry.list_for_personality(self._tool_personality(persona))
            recon_tools = [t for t in tools if t.category == ToolCategory.RECON]
            s1.tool = ", ".join(t.name for t in recon_tools)
            s1.result = f"{len(recon_tools)} recon tools available"
            s1.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s1.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Determine target host ────────────────────────────────────────
        target_host = self._extract_target(objective, ctx)

        # ── Step 2: Passive recon ───────────────────────────────────────
        step_num += 1
        s2 = AgentStep(step_number=step_num, action="passive_recon", tool="dig,curl,openssl")
        steps.append(s2)
        try:
            passive_data = await self.passive_recon(target_host)
            findings = ReconFindings(target=objective)
            findings.dns_records = passive_data.get("dns", {})
            findings.ssl_info = passive_data.get("ssl")
            findings.notes = passive_data.get("notes", [])
            s2.result = f"DNS={len(findings.dns_records)} records, SSL={'yes' if findings.ssl_info else 'no'}"
            s2.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s2.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Step 3: Active scan ─────────────────────────────────────────
        step_num += 1
        ports = ctx.get("ports", self._get_ports_for_personality(persona))
        s3 = AgentStep(step_number=step_num, action="active_scan", tool="nmap")
        steps.append(s3)
        try:
            scan_data = await self.active_scan(target_host, ports)
            findings.open_ports = scan_data.get("open_ports", [])
            findings.services = scan_data.get("services", {})
            findings.os_guess = scan_data.get("os_guess", "unknown")
            s3.result = f"{len(findings.open_ports)} open ports, OS={findings.os_guess}"
            s3.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s3.result = f"Failed: {e}"
            return self._build_result(steps, objective, error=str(e))

        # ── Step 4: Vulnerability hints ─────────────────────────────────
        step_num += 1
        s4 = AgentStep(step_number=step_num, action="vulnerability_analysis")
        steps.append(s4)
        try:
            vulns = self._infer_vulnerabilities(findings)
            findings.vulnerabilities = vulns
            s4.result = f"{len(vulns)} potential vulnerabilities"
            s4.duration_ms = (time.monotonic() - start) * 1000
        except Exception as e:
            s4.result = f"Failed: {e}"

        return AgentResult(
            agent_name=self.name,
            personality=self.personality_mode,
            objective=objective,
            success=True,
            output=self._format_output(findings),
            tools_used=self.select_tools(ToolCategory.RECON),
            steps=steps,
            duration_ms=(time.monotonic() - start) * 1000,
        )

    # ── Target Extraction ─────────────────────────────────────────────────

    def _extract_target(self, objective: str, ctx: dict) -> str:
        """Extract a real IP/hostname from the objective or context."""
        if ctx.get("target"):
            return ctx["target"]

        # Try to find IP-like patterns
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', objective)
        if ips:
            return ips[0]

        # Fallback to localhost
        return "127.0.0.1"

    # ── Passive Recon ────────────────────────────────────────────────────

    async def passive_recon(self, target: str) -> dict:
        """Gather OSINT data — DNS, SSL, HTTP headers."""
        self._log.info("passive_recon_start", target=target)
        loop = asyncio.get_event_loop()

        dns_records = await loop.run_in_executor(None, self._real_dns_lookup, target)
        ssl_info = await loop.run_in_executor(None, self._real_ssl_check, target)
        http_headers = await loop.run_in_executor(None, self._real_http_probe, target)

        notes = []
        if http_headers:
            notes.append(f"HTTP server: {http_headers.get('server', 'unknown')}")
            notes.append(f"HTTP status: {http_headers.get('status', 'unknown')}")

        return {
            "dns": dns_records,
            "ssl": ssl_info,
            "http_headers": http_headers,
            "notes": notes,
        }

    def _real_dns_lookup(self, target: str) -> dict[str, list[str]]:
        """Execute real dig commands for DNS lookup."""
        result: dict[str, list[str]] = {}

        # Only do DNS for hostnames, not bare IPs
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            # Reverse DNS
            try:
                out = subprocess.run(
                    ["dig", "+short", "-x", target],
                    capture_output=True, text=True, timeout=10
                )
                if out.stdout.strip():
                    result["PTR"] = [out.stdout.strip()]
            except Exception:
                pass
            return result

        for record_type in ["A", "AAAA", "MX", "NS"]:
            try:
                out = subprocess.run(
                    ["dig", "+short", record_type, target],
                    capture_output=True, text=True, timeout=10
                )
                lines = [l.strip() for l in out.stdout.strip().split("\n") if l.strip()]
                if lines:
                    result[record_type] = lines
            except Exception:
                pass

        return result

    def _real_ssl_check(self, target: str) -> dict | None:
        """Check SSL/TLS certificate via openssl s_client."""
        try:
            out = subprocess.run(
                ["timeout", "5", "openssl", "s_client", "-connect", f"{target}:443", "-servername", target],
                capture_output=True, text=True, timeout=10,
                input="Q\n"
            )
            output = out.stdout + out.stderr

            info: dict = {"target": target}
            # Extract CN
            cn_match = re.search(r'CN\s*=\s*([^\n]+)', output)
            if cn_match:
                info["cn"] = cn_match.group(1).strip()
            # Extract issuer
            issuer_match = re.search(r'issuer=.*?CN\s*=\s*([^,\n]+)', output)
            if issuer_match:
                info["issuer"] = issuer_match.group(1).strip()
            # Check self-signed
            info["self_signed"] = "self signed certificate" in output.lower()
            # Extract validity
            not_before = re.search(r'notBefore=([^\n]+)', output)
            not_after = re.search(r'notAfter=([^\n]+)', output)
            if not_before:
                info["not_before"] = not_before.group(1).strip()
            if not_after:
                info["not_after"] = not_after.group(1).strip()
            # TLS version
            tls_match = re.search(r'(TLSv[\d.]+)', output)
            if tls_match:
                info["tls_version"] = tls_match.group(1)

            return info
        except Exception as e:
            self._log.debug("ssl_check_failed", target=target, error=str(e))
            return None

    def _real_http_probe(self, target: str) -> dict | None:
        """Probe HTTP/HTTPS with curl to get headers."""
        for scheme in ["https", "http"]:
            try:
                out = subprocess.run(
                    ["curl", "-skI", "-m", "5", f"{scheme}://{target}", "-o", "/dev/null", "-w",
                     "HTTP_CODE:%{http_code}\\nSERVER:%{server}\\nREDIRECT:%{redirect_url}\\n"],
                    capture_output=True, text=True, timeout=10
                )
                headers = {}
                for line in out.stdout.strip().split("\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()
                if headers.get("http_code"):
                    return headers
            except Exception:
                continue
        return None

    # ── Active Scan ──────────────────────────────────────────────────────

    async def active_scan(self, target: str, ports: str | None = None) -> dict:
        """Run a REAL nmap scan against the target."""
        self._log.info("active_scan_start", target=target, ports=ports)
        nmap_args = self._build_nmap_args(ports)
        cmd = ["nmap"] + nmap_args.split() + [target]
        self._log.info("nmap_executing", cmd=" ".join(cmd))

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            )
            return self._parse_real_nmap(result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return {"open_ports": [], "services": {}, "os_guess": "scan timeout", "raw": ""}
        except FileNotFoundError:
            return {"open_ports": [], "services": {}, "os_guess": "nmap not installed", "raw": ""}
        except Exception as e:
            self._log.error("nmap_failed", error=str(e))
            return {"open_ports": [], "services": {}, "os_guess": f"error: {e}", "raw": ""}

    def _build_nmap_args(self, ports: str | None) -> str:
        persona = self.personality.mode.value
        if persona == "narcissism":
            if ports and ports != "1-65535" and "," in str(ports):
                return f"-Pn -T4 -p {ports} --open".strip()
            return "-Pn -T4 --top-ports 100 --open".strip()
        if persona == "psychopathy":
            return f"-Pn -T4 -p- --open --host-timeout 45s --min-rate 5000 --max-retries 2".strip()
        port_list = ports or "22,80,443,8080,8443,3000,3333,5678,8888"
        if port_list == "1-65535":
            port_list = "22,80,443,3000,3333,5678,8000,8080,8083,8443,8642,8888"
        return f"-Pn -T4 -p {port_list} --open".strip()

    def _get_ports_for_personality(self, persona: str) -> str:
        mapping = {
            "narcissism": "22,80,443,3000,3333,5678,8000,8080,8083,8443,8642,8888,2024,4000",
            "psychopathy": "1-65535",
            "mach": "22,80,443,3000,3333,443,5678,8000,8080,8083,8443,8642,8888,2024,4000",
        }
        return mapping.get(persona, mapping["mach"])

    def _parse_real_nmap(self, stdout: str, stderr: str) -> dict:
        """Parse real nmap output into structured data."""
        open_ports: list[int] = []
        services: dict[str, str] = {}
        os_guess = "unknown"

        for line in stdout.split("\n"):
            # Match open port lines: "22/tcp   open  ssh     OpenSSH 9.6p1"
            port_match = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
            if port_match:
                port = int(port_match.group(1))
                service = port_match.group(2)
                open_ports.append(port)
                services[str(port)] = service

            # OS detection
            if "OS details:" in line:
                os_guess = line.split("OS details:", 1)[1].strip()
            elif "Aggressive OS guesses:" in line:
                os_guess = line.split(":", 1)[1].strip().split(",")[0].strip()

        return {
            "open_ports": open_ports,
            "services": services,
            "os_guess": os_guess,
            "raw": stdout[:2000],
        }

    # ── Vulnerability Inference ──────────────────────────────────────────

    def _infer_vulnerabilities(self, findings: ReconFindings) -> list[str]:
        vulns: list[str] = []
        service_vuln_map: dict[str, list[str]] = {
            "ssh": [
                "CVE-2024-6387 (regreSSHion) — vérifier version OpenSSH",
                "SSH exposé — restreindre à tailscale0 si possible",
            ],
            "http": [
                "HTTP sans HTTPS — considérer redirection forcée",
                "Missing security headers (X-Frame-Options, CSP, HSTS)",
            ],
            "https": [
                "Vérifier configuration TLS (version minimale, cipher suites)",
                "Missing HSTS header possible",
            ],
            "mysql": ["CVE-2023-21971", "Restreindre à localhost si non nécessaire"],
            "postgresql": ["Vérifier pg_hba.conf — n'autoriser que local"],
            "redis": ["CVE-2022-0543", "Authentification obligatoire"],
            "mongod": ["Authentification MongoDB obligatoire"],
            "http-proxy": ["Open proxy — vérifier configuration"],
            "cups": ["CUPS inutile sur serveur — désinstaller"],
            "unknown": ["Service inconnu — investiguer"],
        }

        for port, service in findings.services.items():
            for svc_key, cvulns in service_vuln_map.items():
                if svc_key in service.lower():
                    vulns.extend(cvulns)

        # Exposed ports warning
        if 22 in findings.open_ports:
            vulns.append("⚠️ SSH (22) ouvert — vérifier UFW (tailscale0 only recommandé)")
        if 5432 in findings.open_ports and "127.0.0.1" not in str(findings.target):
            vulns.append("⚠️ PostgreSQL (5432) exposé")

        return list(set(vulns))

    def _format_output(self, findings: ReconFindings) -> str:
        lines = [f"Target: {findings.target}"]
        lines.append(f"Open ports: {findings.open_ports}")
        lines.append(f"Services: {findings.services}")
        lines.append(f"OS guess: {findings.os_guess}")
        lines.append(f"Vulnerabilities ({len(findings.vulnerabilities)}):")
        for v in findings.vulnerabilities[:10]:
            lines.append(f"  - {v}")
        if findings.dns_records:
            lines.append(f"DNS: {findings.dns_records}")
        if findings.ssl_info:
            lines.append(f"SSL: CN={findings.ssl_info.get('cn', '?')}, "
                         f"TLS={findings.ssl_info.get('tls_version', '?')}")
        return "\n".join(lines)

    def _build_result(
        self,
        steps: list[AgentStep],
        objective: str,
        error: str | None = None,
    ) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            personality=self.personality_mode,
            objective=objective,
            success=error is None,
            output=error or f"Completed {len(steps)} steps",
            tools_used=self.select_tools(ToolCategory.RECON),
            steps=steps,
            duration_ms=sum(s.duration_ms for s in steps),
        )
