"""Dark Triad — Privilege Escalation Agent.

Vraies techniques d'escalade : sudo, SUID, capabilities, cron, kernel exploits.
Personnalités dictent l'agressivité et la furtivité.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any

import structlog

from navmax.dark_triad.base import AgentResult, AgentStep, BaseAgent
from navmax.dark_triad.ai_router import AIRouter
from navmax.dark_triad.personality import PersonalityProfile
from navmax.dark_triad.sandbox import SandboxManager

logger = structlog.get_logger(__name__)


@dataclass
class PrivescFinding:
    technique: str
    severity: str  # critical, high, medium, low
    description: str
    exploit_command: str = ""
    cve: str | None = None


class PrivescAgent(BaseAgent):
    """Privilege escalation specialist.

    NARCISSUS   → try everything immediately, no verification
    PSYCHOPATH  → ALL techniques in parallel, kernel exploits, dirty pipe
    MACHIAVELLI → enumeration first, stealthy, minimal footprint
    """

    category = "privesc"

    # Known privesc vectors
    _LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"

    def __init__(self, name: str, personality: PersonalityProfile,
                 ai_router: AIRouter, sandbox: SandboxManager) -> None:
        super().__init__(name, personality, ai_router, sandbox)

    async def execute(self, objective: str, context: dict[str, Any] | None = None) -> AgentResult:
        start = time.monotonic()
        steps: list[AgentStep] = []
        persona = self.personality.mode.value
        findings: list[PrivescFinding] = []

        # ── Step 1: Enumerate escalation vectors ────────────────────────
        s1 = AgentStep(step_number=1, action="enumerate_vectors")
        steps.append(s1)

        vectors = await self._enumerate_vectors()
        s1.result = f"{len(vectors)} potential vectors found"
        s1.duration_ms = (time.monotonic() - start) * 1000

        # ── Step 2: Test each vector based on personality ───────────────
        s2 = AgentStep(step_number=2, action="test_exploits")
        steps.append(s2)

        if persona == "psychopathy":
            tasks = [self._test_vector(v) for v in vectors]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, PrivescFinding):
                    findings.append(r)
        elif persona == "narcissism":
            # Try the most severe first, stop on success
            for v in sorted(vectors, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)):
                f = await self._test_vector(v)
                if f.severity in ("critical", "high"):
                    findings.append(f)
                    break
                findings.append(f)
        else:  # Machiavellian — enumerate only, don't execute
            findings = vectors
            for f in findings:
                f.description += " [ENUMERATED ONLY — not exploited for stealth]"

        s2.result = f"{len(findings)} vectors identified"
        s2.duration_ms = (time.monotonic() - start) * 1000

        # ── Step 3: Kernel exploit check (Psychopath only) ─────────────
        if persona == "psychopathy":
            s3 = AgentStep(step_number=3, action="kernel_exploit_check")
            steps.append(s3)
            k = await self._check_kernel_exploits()
            if k:
                findings.extend(k)
                s3.result = f"{len(k)} kernel exploits found"
            else:
                s3.result = "No kernel exploits applicable"
            s3.duration_ms = (time.monotonic() - start) * 1000

        return AgentResult(
            agent_name=self.name, personality=self.personality_mode,
            objective=objective, success=len(findings) > 0,
            output=self._format_output(findings),
            tools_used=[f.technique for f in findings],
            steps=steps, duration_ms=(time.monotonic() - start) * 1000,
        )

    # ── Enumeration ────────────────────────────────────────────────────────

    async def _enumerate_vectors(self) -> list[PrivescFinding]:
        """Enumerate all privilege escalation vectors."""
        loop = asyncio.get_event_loop()
        findings: list[PrivescFinding] = []

        async def _run(cmd: str, timeout_s: int = 10) -> str:
            try:
                result = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["bash", "-c", cmd],
                        capture_output=True, text=True, timeout=timeout_s,
                    ))
                return result.stdout + result.stderr
            except Exception:
                return ""

        # 1. Sudo rights
        sudo_out = await _run("sudo -ln 2>/dev/null || echo 'no sudo access'")
        if "may run" in sudo_out.lower() or "nopasswd" in sudo_out.lower():
            findings.append(PrivescFinding(
                "sudo", "critical",
                f"Sudo privileges: {sudo_out[:200]}",
                "sudo -i", None))
        elif "no sudo" not in sudo_out:
            findings.append(PrivescFinding(
                "sudo", "high", "Sudo available — check permissions", "", None))

        # 2. SUID binaries
        suid_out = await _run("find / -perm -4000 -type f 2>/dev/null | head -20")
        interesting_suid = [l for l in suid_out.split("\n") if l and any(
            x in l for x in ["/bin/", "/usr/bin/", "/sbin/", "python", "perl", "bash", "vim", "nano", "less", "find"])]
        if interesting_suid:
            findings.append(PrivescFinding(
                "suid", "high",
                f"SUID binaries: {', '.join(interesting_suid[:5])}",
                f"{interesting_suid[0]} -p" if interesting_suid else "",
                None))

        # 3. Capabilities
        cap_out = await _run("getcap -r / 2>/dev/null | head -10")
        if cap_out.strip():
            findings.append(PrivescFinding(
                "capabilities", "medium",
                f"Capabilities: {cap_out[:200]}", "", None))

        # 4. Cron jobs
        cron_out = await _run("ls -la /etc/cron* 2>/dev/null; crontab -l 2>/dev/null | head -10")
        if cron_out.strip():
            findings.append(PrivescFinding(
                "cron", "medium",
                f"Cron jobs found — check writable scripts", "", None))

        # 5. Writable config files
        writable_out = await _run("find /etc -writable -type f 2>/dev/null | head -10")
        if writable_out.strip():
            findings.append(PrivescFinding(
                "writable_configs", "high",
                f"Writable configs: {writable_out[:200]}", "", None))

        # 6. Docker group
        groups_out = await _run("groups 2>/dev/null")
        if "docker" in groups_out.lower():
            findings.append(PrivescFinding(
                "docker", "critical",
                "User in docker group → root via container escape",
                "docker run -v /:/host -it alpine chroot /host", "CWE-284"))

        # 7. NFS/SSH keys
        ssh_out = await _run("ls -la ~/.ssh/ 2>/dev/null; cat ~/.ssh/id_rsa 2>/dev/null | head -3")
        if "id_rsa" in ssh_out:
            findings.append(PrivescFinding(
                "ssh_keys", "high",
                "SSH private keys found — potential lateral movement", "", None))

        return findings

    async def _test_vector(self, vector: PrivescFinding) -> PrivescFinding:
        """Test if a privesc vector is exploitable (passive check only)."""
        # For safety, most vectors are just enumerated, not executed
        if vector.technique == "sudo" and "NOPASSWD" in vector.description:
            vector.exploit_command = "# Exploitable: sudo with NOPASSWD"
        return vector

    async def _check_kernel_exploits(self) -> list[PrivescFinding]:
        """Check for applicable kernel exploits."""
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["uname", "-r"], capture_output=True, text=True, timeout=5,
                ))
            kernel = result.stdout.strip()
        except Exception:
            return []

        findings: list[PrivescFinding] = []

        # Known kernel exploits by version
        kernel_exploits = {
            "5.": [
                PrivescFinding("kernel", "critical", "Dirty Pipe (CVE-2022-0847)", "", "CVE-2022-0847"),
                PrivescFinding("kernel", "high", "Dirty Cred (CVE-2022-2588)", "", "CVE-2022-2588"),
            ],
            "6.": [
                PrivescFinding("kernel", "medium", "Kernel 6.x — check for StackRot (CVE-2023-3269)", "", "CVE-2023-3269"),
            ],
        }

        for prefix, exploits in kernel_exploits.items():
            if kernel.startswith(prefix):
                findings.extend(exploits)

        return findings

    def _format_output(self, findings: list[PrivescFinding]) -> str:
        lines = [f"Privilege Escalation — {len(findings)} vectors"]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 4)):
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
            lines.append(f"  {emoji} [{f.severity.upper()}] {f.technique}: {f.description[:150]}")
            if f.exploit_command:
                lines.append(f"     → {f.exploit_command}")
            if f.cve:
                lines.append(f"     CVE: {f.cve}")
        return "\n".join(lines)
