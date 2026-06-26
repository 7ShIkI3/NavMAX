"""Routes API pour le scan de vulnérabilités avec nuclei.

Les endpoints sont montés sous ``/api/v1/nuclei`` dans app.py.
"""

from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Query

from navmax.api.schemas_responses import (
    NucleiScanResponse,
    NucleiStatusResponse,
    NucleiUpdateTemplatesResponse,
)
from navmax.scanner.nuclei_scanner import (
    NucleiNotFoundError,
    NucleiScanner,
    NucleiTimeoutError,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.post(
    "/scan",
    response_model=NucleiScanResponse,
    summary="Lance un scan nuclei sur une cible",
    description="Utilise le moteur de templates nuclei (10 000+ templates communautaires) pour détecter les vulnérabilités connues.",
    responses={
        200: {"description": "Résultat du scan avec les vulnérabilités détectées"},
        400: {"description": "Paramètres invalides (ex: sévérité inconnue)"},
        503: {"description": "Nuclei non installé ou non trouvé"},
        504: {"description": "Timeout du scan nuclei"},
    },
)
async def scan_nuclei(
    target: Annotated[str, Query(description="Cible à scanner (URL, IP, domaine)")],
    templates: Annotated[str | None, Query(description="Templates nuclei (séparés par des virgules). Ex: 'cves/,exposed-panels/' ou None pour tout")] = None,
    severity: Annotated[str | None, Query(description="Filtrer par sévérité (séparés par des virgules). Ex: 'critical,high'")] = None,
    timeout: Annotated[int, Query(ge=30, le=3600, description="Timeout max en secondes (30-3600, défaut: 300)")] = 300,
) -> dict:
    """Lance un scan nuclei sur une cible et retourne les vulnérabilités détectées.

    Utilise le moteur de templates nuclei (10 000+ templates communautaires)
    pour détecter les vulnérabilités connues, expositions, misconfigurations, etc.

    Args:
        target: Cible (URL, IP, domaine ou CIDR).
        templates: Templates spécifiques (optionnel, séparés par des virgules).
        severity: Sévérités à inclure (optionnel, séparés par des virgules).
        timeout: Timeout max en secondes.

    Returns:
        Dict avec les findings et métadonnées du scan.

    """
    scanner = NucleiScanner()

    # Vérifier que nuclei est installé
    installed = await scanner.check_installed()
    if not installed:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "nuclei_not_installed",
                "message": "Le binaire nuclei est requis. Installez-le via : go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "docs": "https://github.com/projectdiscovery/nuclei",
            },
        )

    # Parsing des paramètres optionnels
    template_list: list[str] | None = None
    if templates:
        template_list = [t.strip() for t in templates.split(",") if t.strip()]

    severity_list: list[str] | None = None
    if severity:
        severity_list = [s.strip().lower() for s in severity.split(",") if s.strip()]
        valid = {"critical", "high", "medium", "low", "info"}
        unknown = [s for s in severity_list if s not in valid]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_severity",
                    "message": f"Sévérités invalides : {', '.join(unknown)}. Acceptées : critical, high, medium, low, info",
                },
            )

    logger.info("nuclei_scan_lancé", target=target, templates=template_list, severity=severity_list)
    try:
        findings = await scanner.scan(
            target=target,
            templates=template_list,
            severity=severity_list,
            timeout=timeout,
        )
    except NucleiTimeoutError as e:
        logger.warning("nuclei_scan_timeout", target=target, erreur=str(e))
        raise HTTPException(
            status_code=504,
            detail={"error": "nuclei_timeout", "message": str(e)},
        )
    except NucleiNotFoundError as e:
        logger.exception("nuclei_non_trouvé", erreur=str(e))
        raise HTTPException(
            status_code=503,
            detail={"error": "nuclei_not_found", "message": str(e)},
        )
    except Exception as e:
        logger.exception("nuclei_scan_erreur", target=target, erreur=str(e))
        raise HTTPException(
            status_code=500,
            detail={"error": "nuclei_scan_failed", "message": str(e)},
        )

    logger.info("nuclei_scan_terminé", target=target, findings_count=len(findings))

    findings_dicts = [
        {
            "template_id": f.template_id,
            "name": f.name,
            "severity": f.severity,
            "host": f.host,
            "matched_at": f.matched_at,
            "description": f.description,
            "cvss_score": f.cvss_score,
            "cve_ids": f.cve_ids,
            "reference_urls": f.reference_urls,
            "extracted_results": f.extracted_results[:5],
        }
        for f in findings
    ]

    return {
        "target": target,
        "findings_count": len(findings),
        "findings": findings_dicts,
    }


@router.post(
    "/update-templates",
    response_model=NucleiUpdateTemplatesResponse,
    summary="Met à jour les templates nuclei",
    description="Télécharge la dernière version des templates communautaires (10 000+ templates) via nuclei -update-templates.",
    responses={
        200: {"description": "Templates mis à jour avec succès"},
        503: {"description": "Nuclei non installé"},
    },
)
async def update_nuclei_templates() -> NucleiUpdateTemplatesResponse:
    """Met à jour les templates nuclei officiels."""
    installed = await NucleiScanner().check_installed()
    if not installed:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "nuclei_not_installed",
                "message": "Le binaire nuclei est requis.",
            },
        )

    try:
        await NucleiScanner.update_templates()
    except OSError as exc:
        logger.exception("nuclei_install_templates_erreur_os", erreur=str(exc))
        raise HTTPException(
            status_code=500,
            detail={"error": "template_install_failed", "message": str(exc)},
        ) from exc
    except Exception as exc:
        logger.exception("nuclei_install_templates_erreur", erreur=str(exc))
        raise HTTPException(
            status_code=500,
            detail={"error": "template_install_failed", "message": str(exc)},
        ) from exc

    logger.info("nuclei_templates_mis_à_jour")
    return {"status": "ok", "message": "Templates nuclei mis à jour avec succès."}


@router.get(
    "/status",
    response_model=NucleiStatusResponse,
    summary="Vérifie l'installation nuclei",
    description="Vérifie si le binaire nuclei est installé et si les templates sont disponibles.",
    responses={200: {"description": "État de l'installation nuclei"}},
)
async def nuclei_status() -> NucleiStatusResponse:
    """Vérifie si nuclei est installé et les templates disponibles."""
    scanner = NucleiScanner()
    installed = await scanner.check_installed()
    templates = await scanner.check_templates() if installed else False
    return {
        "installed": installed,
        "templates_available": templates,
        "binary_path": scanner._binary if installed else None,
    }
