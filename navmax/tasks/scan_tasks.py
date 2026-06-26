"""Tâches Celery NavMAX — scans longue durée en background worker.

Chaque tâche est bind=True pour permettre update_state().
Les appels async sont wrappés dans asyncio.run() car Celery workers
tournent dans un processus séparé sans boucle d'événements.
"""

import asyncio
import json
import shutil
import subprocess
import uuid
from datetime import UTC, datetime

from navmax.core.logging import get_logger
from navmax.db.engine import async_session
from navmax.db.models import Scan, Service, Target, Vulnerability
from navmax.scanner.engine import parse_ports
from navmax.scanner.nmap_scanner import NmapScanner
from navmax.tasks import celery_app

logger = get_logger(__name__)


# ── Helpers asynchrones ────────────────────────────────────────


def _run_async(coro):
    """Wrapper pour exécuter une coroutine dans un contexte Celery (sync)."""
    return asyncio.run(coro)


# ── Tâche : run_nmap_scan ──────────────────────────────────────


@celery_app.task(bind=True, max_retries=3, time_limit=600, soft_time_limit=540)
def run_nmap_scan(self, target: str, ports: str, profile: str = "default") -> dict:
    """Lance un scan Nmap complet sur une cible et persiste les résultats.

    Args:
        target: Cible (IP ou hostname)
        ports: Ports au format Nmap (ex: "22,80,443" ou "1-1000,3306")
        profile: Profil de scan (default, fast, intense)

    Returns:
        Dict récapitulatif : ports ouverts, services détectés, OS, etc.

    """
    scan_id = str(uuid.uuid4())
    self.update_state(
        state="PROGRESS",
        meta={"status": "Scan nmap en cours...", "progress": 0, "scan_id": scan_id},
    )

    def _execute() -> dict:
        """Exécution synchrone wrappant les appels async."""
        # ── 1. Valider la cible ─────────────────────────────────
        if not target or not target.strip():
            msg = "Cible invalide : chaîne vide"
            raise ValueError(msg)

        # ── 2. Parser les ports ─────────────────────────────────
        port_list = parse_ports(ports) if ports else []
        if not port_list:
            msg = "Aucun port valide spécifié"
            raise ValueError(msg)

        logger.info("nmap_task_demarrage", target=target, ports=len(port_list), profile=profile)

        # ── 3. Créer / récupérer la cible en base ───────────────
        async def _find_or_create_target() -> tuple[str, str]:
            async with async_session() as db:
                # Chercher une cible existante par adresse
                stmt = __import__("sqlalchemy").select(Target).where(Target.address == target)
                result = await db.execute(stmt)
                db_target = result.scalar_one_or_none()

                if db_target is None:
                    db_target = Target(
                        id=str(uuid.uuid4()),
                        name=target,
                        address=target,
                        kind="host",
                        created_at=datetime.now(UTC),
                        updated_at=datetime.now(UTC),
                    )
                    db.add(db_target)
                    await db.commit()
                    await db.refresh(db_target)

                return db_target.id, db_target.name

        try:
            target_id, _target_name = _run_async(_find_or_create_target())
        except (ConnectionError, TimeoutError) as exc:
            raise self.retry(exc=exc, countdown=30, max_retries=3)

        # ── 4. Créer un enregistrement Scan ─────────────────────
        async def _create_scan_record() -> str:
            async with async_session() as db:
                db_scan = Scan(
                    id=scan_id,
                    target_id=target_id,
                    scan_type=f"nmap_{profile}",
                    ports=ports,
                    status="running",
                    progress=0.0,
                    started_at=datetime.now(UTC),
                )
                db.add(db_scan)
                await db.commit()
                return db_scan.id

        try:
            _run_async(_create_scan_record())
        except (ConnectionError, TimeoutError) as exc:
            raise self.retry(exc=exc, countdown=30, max_retries=3)

        self.update_state(
            state="PROGRESS",
            meta={"status": "Scan Nmap en cours...", "progress": 10, "scan_id": scan_id},
        )

        # ── 5. Lancer le scan Nmap asynchrone ───────────────────
        async def _run_nmap_scan() -> dict:
            scanner = NmapScanner()
            result = await scanner.scan(
                host=target,
                ports=port_list,
                args="-sV" if profile == "fast" else "-sV -O --osscan-guess",
                timeout=120 if profile == "fast" else 300,
            )
            return {
                "host": result.host,
                "status": result.status,
                "ports": result.ports,
                "os_matches": result.os_matches,
                "os_cpe": result.os_cpe,
                "uptime": result.uptime,
                "mac_address": result.mac_address,
                "error": result.error,
            }

        try:
            scan_result = _run_async(_run_nmap_scan())
        except (ConnectionError, TimeoutError) as exc:
            raise self.retry(exc=exc, countdown=30, max_retries=3)

        self.update_state(
            state="PROGRESS",
            meta={"status": "Sauvegarde des résultats...", "progress": 70, "scan_id": scan_id},
        )

        # ── 6. Persister les résultats en DB ────────────────────
        async def _persist_results() -> None:
            async with async_session() as db:
                db_scan = await db.get(Scan, scan_id)
                if db_scan is None:
                    logger.error("scan_introuvable_persist", scan_id=scan_id)
                    return

                open_ports = []
                services_list = []

                for port_data in scan_result.get("ports", {}).values():
                    if isinstance(port_data, dict) and port_data.get("state") == "open":
                        open_ports.append(port_data)
                        svc = Service(
                            id=str(uuid.uuid4()),
                            target_id=target_id,
                            scan_id=scan_id,
                            port=port_data.get("port", 0),
                            protocol=port_data.get("protocol", "tcp"),
                            state="open",
                            service_name=port_data.get("service", ""),
                            version=port_data.get("version", ""),
                            banner=port_data.get("banner", ""),
                            extra_data=json.dumps(
                                {
                                    k: v
                                    for k, v in port_data.items()
                                    if k in ("product", "extrainfo", "cpe", "script_results") and v
                                },
                            ),
                        )
                        db.add(svc)
                        services_list.append(svc)

                # Résumé
                os_info = ""
                if scan_result.get("os_matches"):
                    best = scan_result["os_matches"][0]
                    os_info = f"{best.get('name', '?')} (précision: {best.get('accuracy', 0)}%)"

                summary_parts = [
                    f"Cible : {target}",
                    f"Ports scannés : {len(port_list)}",
                    f"Ports ouverts : {len(open_ports)}",
                    f"OS : {os_info or 'Non détecté'}",
                    f"Statut hôte : {scan_result.get('status', 'inconnu')}",
                ]

                db_scan.result_summary = " | ".join(summary_parts)
                db_scan.raw_result = json.dumps(scan_result, ensure_ascii=False, default=str)
                db_scan.progress = 100.0
                db_scan.status = "completed"
                db_scan.finished_at = datetime.now(UTC)

                # Mettre à jour la cible
                db_target = await db.get(Target, target_id)
                if db_target:
                    db_target.alive = scan_result.get("status") == "up"
                    db_target.updated_at = datetime.now(UTC)

                await db.commit()

                logger.info(
                    "nmap_task_termine",
                    scan_id=scan_id,
                    target=target,
                    open=len(open_ports),
                )

        try:
            _run_async(_persist_results())
        except (ConnectionError, TimeoutError) as exc:
            raise self.retry(exc=exc, countdown=30, max_retries=3)

        self.update_state(
            state="SUCCESS",
            meta={
                "status": "Scan terminé",
                "progress": 100,
                "scan_id": scan_id,
            },
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "target_id": target_id,
            "host_status": scan_result.get("status"),
            "ports_scanned": len(port_list),
            "ports_open": len(
                [
                    p
                    for p in scan_result.get("ports", {}).values()
                    if isinstance(p, dict) and p.get("state") == "open"
                ],
            ),
            "os": scan_result.get("os_matches", [{}])[0].get("name", "")
            if scan_result.get("os_matches")
            else "",
            "error": scan_result.get("error"),
        }

    try:
        return _execute()
    except Exception as e:
        logger.exception("nmap_task_erreur", target=target, error=str(e))
        self.update_state(
            state="FAILURE",
            meta={"status": f"Échec : {e!s}", "progress": 0},
        )
        raise


# ── Tâche : run_nuclei_scan ────────────────────────────────────


@celery_app.task(bind=True, max_retries=3, time_limit=660, soft_time_limit=600)
def run_nuclei_scan(
    self,
    target: str,
    templates: list[str] | None = None,
    severity: list[str] | None = None,
) -> dict:
    """Lance un scan de vulnérabilités Nuclei sur une cible.

    Args:
        target: Cible (IP, hostname ou URL)
        templates: Templates Nuclei à utiliser (ex: ["cves", "misconfiguration"])
        severity: Niveaux de sévérité (ex: ["critical", "high", "medium"])

    Returns:
        Dict avec la liste des vulnérabilités découvertes

    """
    self.update_state(
        state="PROGRESS",
        meta={"status": "Scan nuclei en cours...", "progress": 0},
    )

    def _execute() -> dict:
        scan_id = str(uuid.uuid4())

        # Vérifier si nuclei est installé
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            logger.warning("nuclei_non_installe", target=target)
            self.update_state(
                state="SUCCESS",
                meta={"status": "Nuclei non installé — scan ignoré", "progress": 100},
            )
            return {
                "scan_id": scan_id,
                "target": target,
                "status": "skipped",
                "note": "nuclei n'est pas installé sur le système. "
                "Installez-le via 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'",
                "vulnerabilities": [],
            }

        logger.info("nuclei_task_demarrage", target=target, templates=templates, severity=severity)

        self.update_state(
            state="PROGRESS",
            meta={"status": "Analyse des vulnérabilités...", "progress": 50, "scan_id": scan_id},
        )

        # ── Trouver/créer la cible en DB ────────────────────────
        async def _find_or_create_target() -> str:
            async with async_session() as db:
                stmt = __import__("sqlalchemy").select(Target).where(Target.address == target)
                result = await db.execute(stmt)
                db_target = result.scalar_one_or_none()
                if db_target is None:
                    db_target = Target(
                        id=str(uuid.uuid4()),
                        name=target,
                        address=target,
                        kind="host",
                    )
                    db.add(db_target)
                    await db.commit()
                    await db.refresh(db_target)
                return db_target.id

        try:
            target_id = _run_async(_find_or_create_target())
        except (ConnectionError, TimeoutError) as exc:
            raise self.retry(exc=exc, countdown=30, max_retries=3)

        # ── Construire la commande nuclei ───────────────────────
        cmd = [nuclei_path, "-target", target, "-json", "-silent"]
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        # Exécuter nuclei en sous-processus
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            try:
                stdout, _ = proc.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                logger.exception("nuclei_timeout", target=target)
                return {
                    "scan_id": scan_id,
                    "target": target,
                    "status": "timeout",
                    "vulnerabilities": [],
                }

            vulnerabilities = []
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    vuln_data = json.loads(line)
                    vuln = {
                        "template_id": vuln_data.get("template-id", ""),
                        "name": vuln_data.get("info", {}).get("name", ""),
                        "severity": vuln_data.get("info", {}).get("severity", "unknown"),
                        "description": vuln_data.get("info", {}).get("description", ""),
                        "matched_at": vuln_data.get("matched-at", ""),
                        "type": vuln_data.get("type", ""),
                        "host": target,
                    }
                    vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue

            # ── Sauvegarder les vulnérabilités en DB ────────────
            async def _persist_vulns() -> None:
                async with async_session() as db:
                    for v in vulnerabilities:
                        vuln = Vulnerability(
                            id=str(uuid.uuid4()),
                            target_id=target_id,
                            cve_id=v.get("template_id", ""),
                            title=v.get("name", "Vulnérabilité détectée"),
                            description=v.get("description", ""),
                            severity=v.get("severity", "unknown"),
                            evidence=json.dumps(v),
                        )
                        db.add(vuln)
                    await db.commit()

            try:
                _run_async(_persist_vulns())
            except (ConnectionError, TimeoutError) as exc:
                raise self.retry(exc=exc, countdown=30, max_retries=3)

            logger.info(
                "nuclei_task_termine",
                target=target,
                vulns=len(vulnerabilities),
            )

            self.update_state(
                state="SUCCESS",
                meta={"status": "Scan terminé", "progress": 100, "scan_id": scan_id},
            )

            return {
                "scan_id": scan_id,
                "target": target,
                "status": "completed",
                "vulnerabilities_count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
            }

        except FileNotFoundError:
            return {
                "scan_id": scan_id,
                "target": target,
                "status": "skipped",
                "note": "Binaire nuclei introuvable (shutil.which a réussi mais subprocess échoue)",
                "vulnerabilities": [],
            }
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

    try:
        return _execute()
    except Exception as e:
        logger.exception("nuclei_task_erreur", target=target, error=str(e))
        self.update_state(
            state="FAILURE",
            meta={"status": f"Échec : {e!s}", "progress": 0},
        )
        raise


# ── Tâche : run_mission ────────────────────────────────────────


@celery_app.task(bind=True, max_retries=1, time_limit=3600, soft_time_limit=3540)
def run_mission(self, mission_objective: str) -> dict:
    """Planifie et exécute une mission complète via MissionPlanner.

    Args:
        mission_objective: Description en langage naturel de la mission
            (ex: "Trouve la base de données sensible sur 10.0.0.0/24")

    Returns:
        Dict avec les résultats agrégés de toutes les phases

    """
    mission_id = str(uuid.uuid4())
    self.update_state(
        state="PROGRESS",
        meta={
            "status": "Mission en cours de planification...",
            "progress": 0,
            "mission_id": mission_id,
        },
    )

    def _execute() -> dict:
        from navmax.ai.engine import AIEngine
        from navmax.ai.mission_planner import MissionPlanner

        logger.info("mission_task_demarrage", objective=mission_objective)

        # ── 1. Initialiser l'AIEngine ───────────────────────────
        self.update_state(
            state="PROGRESS",
            meta={
                "status": "Initialisation du moteur IA...",
                "progress": 5,
                "mission_id": mission_id,
            },
        )

        async def _init_engine():
            engine = AIEngine()
            await engine.initialize()
            return engine

        try:
            engine = _run_async(_init_engine())
        except (ConnectionError, TimeoutError) as exc:
            raise self.retry(exc=exc, countdown=30, max_retries=1)

        # ── 2. Planifier la mission ─────────────────────────────
        self.update_state(
            state="PROGRESS",
            meta={
                "status": "Planification de la mission...",
                "progress": 15,
                "mission_id": mission_id,
            },
        )

        planner = MissionPlanner(engine)
        plan = _run_async(planner.plan(mission_objective))

        total_phases = plan.phase_count
        logger.info("mission_planifiee", phases=total_phases, modules=plan.modules_used)

        # ── 3. Exécuter chaque phase ────────────────────────────
        phase_results = []
        ordered_phases = plan.topological_order()

        for idx, phase in enumerate(ordered_phases):
            phase_progress = 15 + int((idx + 1) / max(total_phases, 1) * 80)

            self.update_state(
                state="PROGRESS",
                meta={
                    "status": f"Phase {idx + 1}/{total_phases} : {phase.description[:80]}",
                    "progress": phase_progress,
                    "mission_id": mission_id,
                    "current_phase": phase.id,
                },
            )

            # Marquer comme running
            phase.status = __import__(
                "navmax.ai.mission_planner",
            ).mission_planner.PhaseStatus.RUNNING

            try:
                result = _execute_phase(phase.module_needed, phase.parameters)
                phase.status = __import__(
                    "navmax.ai.mission_planner",
                ).mission_planner.PhaseStatus.COMPLETED
                phase.result = result

                phase_results.append(
                    {
                        "phase_id": phase.id,
                        "description": phase.description,
                        "module": phase.module_needed,
                        "status": "completed",
                        "result": result,
                    },
                )

            except Exception as e:
                phase.status = __import__(
                    "navmax.ai.mission_planner",
                ).mission_planner.PhaseStatus.FAILED
                phase.error = str(e)

                phase_results.append(
                    {
                        "phase_id": phase.id,
                        "description": phase.description,
                        "module": phase.module_needed,
                        "status": "failed",
                        "error": str(e),
                    },
                )

                logger.exception("mission_phase_echouee", phase=phase.id, error=str(e))

        # ── 4. Finaliser ────────────────────────────────────────
        success_count = sum(1 for r in phase_results if r["status"] == "completed")
        failed_count = sum(1 for r in phase_results if r["status"] == "failed")

        self.update_state(
            state="SUCCESS",
            meta={
                "status": "Mission terminée",
                "progress": 100,
                "mission_id": mission_id,
            },
        )

        logger.info(
            "mission_task_terminee",
            mission_id=mission_id,
            phases=total_phases,
            success=success_count,
            failed=failed_count,
        )

        return {
            "mission_id": mission_id,
            "objective": mission_objective,
            "total_phases": total_phases,
            "successful_phases": success_count,
            "failed_phases": failed_count,
            "modules_used": list(plan.modules_used),
            "phases": phase_results,
        }

    try:
        return _execute()
    except Exception as e:
        logger.exception("mission_task_erreur", objective=mission_objective, error=str(e))
        self.update_state(
            state="FAILURE",
            meta={"status": f"Échec de la mission : {e!s}", "progress": 0},
        )
        raise


# ── Helper : exécution d'une phase de mission ──────────────────


def _execute_phase(module: str, parameters: dict) -> dict:
    """Exécute une phase de mission selon le module requis.

    Args:
        module: Nom du module (scanner, osint, exploit, proxy, sandbox)
        parameters: Paramètres de la phase

    Returns:
        Résultat de l'exécution

    """
    module = module.lower().strip()

    if module == "scanner":
        target = parameters.get("target", parameters.get("host", ""))
        ports = parameters.get("ports", "22,80,443,8080,8443")
        profile = parameters.get("profile", "fast")

        if not target:
            return {"error": "Aucune cible spécifiée pour le scan"}

        # Lancer un sous-scan nmap
        result = run_nmap_scan(target, ports, profile)
        return {
            "scan_id": result.get("scan_id"),
            "target": target,
            "ports_open": result.get("ports_open", 0),
            "os": result.get("os", ""),
        }

    if module == "osint":
        target = parameters.get("target", parameters.get("domain", ""))
        return {
            "module": "osint",
            "target": target,
            "status": "not_implemented",
            "note": "Le module OSINT en tâche Celery n'est pas encore implémenté",
        }

    if module == "exploit":
        target = parameters.get("target", parameters.get("host", ""))
        service_hint = parameters.get("service_hint", "")
        return {
            "module": "exploit",
            "target": target,
            "service_hint": service_hint,
            "status": "not_implemented",
            "note": "Le module Exploit en tâche Celery n'est pas encore implémenté",
        }

    if module == "proxy":
        target = parameters.get("target", parameters.get("url", ""))
        return {
            "module": "proxy",
            "target": target,
            "status": "not_implemented",
            "note": "Le module Proxy en tâche Celery n'est pas encore implémenté",
        }

    if module == "sandbox":
        return {
            "module": "sandbox",
            "status": "not_implemented",
            "note": "Le module Sandbox en tâche Celery n'est pas encore implémenté",
        }

    return {
        "module": module,
        "status": "unknown_module",
        "error": f"Module inconnu : {module}",
    }
