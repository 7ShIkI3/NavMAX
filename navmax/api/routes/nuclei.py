"""Routes API pour le scan de vulnérabilités avec nuclei."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query

from navmax.scanner.nuclei_scanner import (
    NucleiScanner,
    NucleiNotFoundError,
    NucleiTimeoutError,
)

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.post("/nuclei", tags=["Nuclei"])
async def scan_nuclei(
    target: str = Query(..., description="Cible à scanner (URL, IP, domaine)"),
    templates: str | None = Query(
        None,
        description="Templates nuclei (séparés par des virgules). Ex: 'cves/,exposed-panels/' ou None pour tout",
    ),
    severity: str | None = Query(
        None,
        description="Filtrer par sévérité (séparés par des virgules). Ex: 'critical,high'",
    ),
    timeout: int = Query(
        300,
        ge=30,
        le=3600,
        description="Timeout max en secondes (30-3600, défaut: 300)",
    ),
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

    try:
        findings = await scanner.scan(
            target=target,
            templates=template_list,
            severity=severity_list,
            timeout=timeout,
        )
    except NucleiTimeoutError as e:
        raise HTTPException(
            status_code=504,
            detail={"error": "nuclei_timeout", "message": str(e)},
        )
    except Exception as e:
        logger.error("nuclei_scan_error", target=target, error=str(e))
        raise HTTPException(
            status_code=500,
            detail={"error": "nuclei_scan_failed", "message": str(e)},
        )

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


@router.post("/nuclei/install-templates", tags=["Nuclei"])
async def install_nuclei_templates() -> dict:
    """Télécharge/met à jour les templates nuclei officiels.

    Synchronise la dernière version des templates communautaires
    (10 000+ templates de vulnérabilités).
    """
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
        await NucleiScanner.install_templates()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "template_install_failed", "message": str(e)},
        )

    return {"status": "ok", "message": "Templates nuclei mis à jour avec succès."}


@router.get("/nuclei/status", tags=["Nuclei"])
async def nuclei_status() -> dict:
    """Vérifie si nuclei est installé et disponible."""
    scanner = NucleiScanner()
    installed = await scanner.check_installed()
    return {"installed": installed, "binary_path": scanner._binary if installed else None}
