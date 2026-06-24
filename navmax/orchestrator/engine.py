"""
MissionOrchestrator — exécution autonome "One-Click" de missions.

Reçoit un objectif en langage naturel, planifie, exécute les phases
dans l'ordre topologique, et génère un rapport.
"""

from dataclasses import dataclass, field
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class MissionResult:
    """Résultat d'une mission exécutée."""
    objective: str
    target: Optional[str] = None
    phases_executed: int = 0
    phases_succeeded: int = 0
    phases_failed: int = 0
    results: dict[str, dict] = field(default_factory=dict)
    report: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def success_rate(self) -> float:
        if self.phases_executed == 0:
            return 0.0
        return self.phases_succeeded / self.phases_executed


class MissionOrchestrator:
    """Orchestrateur de mission One-Click.

    Usage:
        orch = MissionOrchestrator(planner, scanner, exploit_loader, osint_orch, audit)
        result = await orch.execute("Trouve la BDD sensible sur 10.0.0.0/24")
        print(f"{result.phases_succeeded}/{result.phases_executed} phases OK")
    """

    def __init__(self, planner=None, scanner=None, exploit_loader=None,
                 osint_orchestrator=None, audit=None, ai_engine=None,
                 reporter=None):
        self.planner = planner        # MissionPlanner
        self.scanner = scanner         # Scanner (TCP + contextuel)
        self.exploits = exploit_loader # ExploitLoader
        self.osint = osint_orchestrator # OSINTOrchestrator
        self.audit = audit             # AuditLogger
        self.ai = ai_engine            # AIEngine
        self.reporter = reporter       # ReportGenerator

    async def execute(self, objective: str, *,
                      target: Optional[str] = None,
                      constraints: Optional[str] = None,
                      dry_run: bool = False) -> MissionResult:
        """Exécute une mission complète.

        Args:
            objective: Objectif en langage naturel
            target: Cible optionnelle
            constraints: Contraintes
            dry_run: Si True, planifie sans exécuter

        Returns:
            MissionResult avec le résumé
        """
        import time
        t_start = time.monotonic()

        result = MissionResult(objective=objective, target=target)
        logger.info("mission_start", objective=objective, target=target)

        try:
            # Étape 1: Planifier
            if not self.planner:
                result.error = "No mission planner configured"
                return result

            plan = await self.planner.plan(
                objective, target=target, constraints=constraints
            )
            logger.info("mission_planned", phases=plan.phase_count)

            if dry_run:
                result.phases_executed = plan.phase_count
                result.duration_seconds = time.monotonic() - t_start
                return result

            # Étape 2: Exécuter les phases dans l'ordre topologique
            for phase in plan.topological_order():
                logger.info("executing_phase", phase=phase.id,
                            module=phase.module_needed)

                # Audit
                audit_ctx = None
                if self.audit:
                    audit_ctx = self.audit.track(
                        "mission_execute",
                        f"orchestrator.{phase.module_needed}",
                        phase_id=phase.id,
                        parameters=phase.parameters,
                    )

                try:
                    if audit_ctx:
                        await audit_ctx.__aenter__()

                    phase_result = await self._execute_phase(phase)

                    if audit_ctx:
                        if isinstance(audit_ctx, object) and hasattr(audit_ctx, 'result_summary'):
                            audit_ctx.result_summary = phase_result

                    result.results[phase.id] = phase_result or {}
                    result.phases_succeeded += 1

                except Exception as e:
                    logger.error("phase_failed", phase=phase.id, error=str(e))
                    result.results[phase.id] = {"error": str(e)}
                    result.phases_failed += 1
                finally:
                    if audit_ctx:
                        try:
                            await audit_ctx.__aexit__(None, None, None)
                        except Exception:
                            pass

                result.phases_executed += 1

        except Exception as e:
            logger.error("mission_failed", error=str(e))
            result.error = str(e)

        result.duration_seconds = time.monotonic() - t_start
        logger.info("mission_complete",
                     phases=result.phases_executed,
                     succeeded=result.phases_succeeded,
                     failed=result.phases_failed)

        # Étape 3: Générer le rapport
        if self.reporter:
            try:
                result.report = await self.reporter.generate(result)
            except Exception as e:
                logger.warning("report_failed", error=str(e))

        return result

    async def _execute_phase(self, phase) -> Optional[dict]:
        """Exécute une phase selon son module."""
        module = phase.module_needed
        params = phase.parameters

        if module == "scanner" and self.scanner:
            target = params.get("target", "")
            ports_str = params.get("ports", "22,80,443,8080")
            ports = self._parse_ports(ports_str)

            # Utiliser le scanner contextuel si dispo
            if hasattr(self.scanner, 'scan'):
                results = await self.scanner.scan(target, ports=ports)
                return {
                    "hosts_scanned": 1,
                    "open_ports": len([r for r in results if not (hasattr(r, 'error') and r.error)]),
                    "services": [
                        {"port": r.port, "service": r.service, "version": r.version}
                        for r in results if not (hasattr(r, 'error') and r.error)
                    ],
                }

        elif module == "osint" and self.osint:
            target = params.get("target", "")
            if hasattr(self.osint, 'investigate_domain'):
                await self.osint.investigate_domain(target)
                return {"status": "completed", "target": target}

        elif module == "exploit" and self.exploits:
            service_hint = params.get("service_hint", "")
            target = params.get("target", "")

            # Chercher un exploit correspondant
            results = self.exploits.search(query=service_hint)
            if results:
                exploit_name = results[0] if isinstance(results[0], str) else results[0].get("name", "")
                return {
                    "exploit_found": True,
                    "exploit": exploit_name,
                    "candidates": len(results),
                }
            return {"exploit_found": False, "candidates": 0}

        elif module == "proxy" and params:
            return {"status": "not_implemented", "module": "proxy"}

        elif module == "sandbox" and params:
            return {"status": "not_implemented", "module": "sandbox"}

        return {"status": "skipped", "reason": f"No handler for {module}"}

    def _parse_ports(self, ports_str: str) -> list[int]:
        """Parse une chaîne de ports en liste."""
        ports = []
        for part in ports_str.replace(" ", "").split(","):
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            elif part:
                ports.append(int(part))
        return sorted(set(ports)) if ports else [22, 80, 443]
