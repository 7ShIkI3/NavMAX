"""
API Routes — Active Directory & LDAP.

Endpoints REST pour l'énumération, le scanning, et l'analyse AD.

POST /api/v1/ad/enumerate      — Énumération complète du domaine
POST /api/v1/ad/scan           — Scan de vulnérabilités
POST /api/v1/ad/analyze        — Analyse des chemins d'attaque
POST /api/v1/ad/spray          — Password spraying (⚠️ sensible)
GET  /api/v1/ad/graph/export   — Export BloodHound JSON
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from navmax.db.engine import get_session
from navmax.core.logging import get_logger

router = APIRouter(prefix="/api/v1/ad", tags=["Active Directory"])
logger = get_logger(__name__)


# ── Schemas ────────────────────────────────────────────────────

class ADEnumerateRequest(BaseModel):
    server: str
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: bool = True


class ADScanRequest(BaseModel):
    server: str
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None


class ADAnalyzeRequest(BaseModel):
    server: str
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None


class ADSprayRequest(BaseModel):
    server: str
    domain: str
    username: str
    password: str
    target_users: Optional[list[str]] = None
    password_list: Optional[list[str]] = None
    safe_mode: bool = True


# ── Routes ─────────────────────────────────────────────────────

@router.post("/enumerate")
async def ad_enumerate(req: ADEnumerateRequest):
    """Énumération complète Active Directory.

    Retourne le résumé de la DomainMap : comptage users, groups, etc.
    """
    from navmax.ad.connector import ADConfig, ADAuthMethod, ADConnector
    from navmax.ad.enumerator import ADEnumerator

    config = ADConfig(
        server=req.server,
        domain=req.domain,
        username=req.username,
        password=req.password,
        auth_method=ADAuthMethod.SIMPLE if req.username else ADAuthMethod.ANONYMOUS,
        use_ssl=req.use_ssl,
    )

    connector = ADConnector(config)
    try:
        await connector.connect()
        enumerator = ADEnumerator(connector)
        domain_map = await enumerator.enumerate_all()
        logger.info(
            "ad_énumération_réussie",
            server=req.server,
            domain=req.domain,
            users=len(domain_map.users),
        )
        return {
            "status": "success",
            "domain": domain_map.domain.name,
            "users": len(domain_map.users),
            "groups": len(domain_map.groups),
            "computers": len(domain_map.computers),
            "ous": len(domain_map.ous),
            "gpos": len(domain_map.gpos),
            "trusts": len(domain_map.trusts),
            "privileged_users": len(domain_map.privileged_users),
            "kerberoastable_users": len(domain_map.kerberoastable_users),
            "summary": domain_map.summary(),
        }
    except ConnectionError as exc:
        logger.warning("ad_connexion_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=502, detail=f"Connexion AD échouée : {exc}") from exc
    except PermissionError as exc:
        logger.warning("ad_auth_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=401, detail=f"Authentification AD échouée : {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — erreurs LDAP/AD imprévisibles
        logger.error("ad_énumération_erreur", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await connector.close()


@router.post("/scan")
async def ad_scan(req: ADScanRequest):
    """Scan de vulnérabilités Active Directory."""
    from navmax.ad.connector import ADConfig, ADAuthMethod, ADConnector
    from navmax.ad.enumerator import ADEnumerator
    from navmax.ad.vuln_scanner import ADVulnScanner

    config = ADConfig(
        server=req.server,
        domain=req.domain,
        username=req.username,
        password=req.password,
        auth_method=ADAuthMethod.SIMPLE if req.username else ADAuthMethod.ANONYMOUS,
    )

    connector = ADConnector(config)
    try:
        await connector.connect()
        enumerator = ADEnumerator(connector)
        domain_map = await enumerator.enumerate_all()

        scanner = ADVulnScanner(connector)
        report = await scanner.scan_all(domain_map)

        logger.info(
            "ad_scan_réussi",
            server=req.server,
            domain=req.domain,
            findings=report.total_findings,
        )
        return {
            "status": "success",
            "domain": report.domain,
            "total_findings": report.total_findings,
            "critical": report.critical_count,
            "high": report.high_count,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "affected_count": f.affected_count,
                    "remediation": f.remediation,
                }
                for f in report.findings
            ],
        }
    except ConnectionError as exc:
        logger.warning("ad_connexion_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=502, detail=f"Connexion AD échouée : {exc}") from exc
    except PermissionError as exc:
        logger.warning("ad_auth_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=401, detail=f"Authentification AD échouée : {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — erreurs LDAP/AD imprévisibles
        logger.error("ad_scan_erreur", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await connector.close()


@router.post("/analyze")
async def ad_analyze(req: ADAnalyzeRequest):
    """Analyse des chemins d'attaque + graphe BloodHound."""
    from navmax.ad.connector import ADConfig, ADAuthMethod, ADConnector
    from navmax.ad.enumerator import ADEnumerator
    from navmax.ad.trust_graph import ADTrustGraph
    from navmax.ad.attack_paths import AttackPathAnalyzer

    config = ADConfig(
        server=req.server,
        domain=req.domain,
        username=req.username,
        password=req.password,
        auth_method=ADAuthMethod.SIMPLE if req.username else ADAuthMethod.ANONYMOUS,
    )

    connector = ADConnector(config)
    try:
        await connector.connect()
        enumerator = ADEnumerator(connector)
        domain_map = await enumerator.enumerate_all()

        graph = ADTrustGraph()
        graph.build(domain_map)

        analyzer = AttackPathAnalyzer()
        analysis = await analyzer.analyze(graph)

        logger.info(
            "ad_analyse_réussie",
            server=req.server,
            domain=req.domain,
            risk=analysis.overall_risk_level,
        )
        return {
            "status": "success",
            "domain": domain_map.domain.name,
            "overall_risk": analysis.overall_risk_level,
            "exposed_users": analysis.exposed_users_count,
            "kerberoastable_paths": analysis.kerberoastable_accounts_leading_to_da,
            "critical_paths": [
                {
                    "name": p.name,
                    "source": p.source,
                    "target": p.target,
                    "risk_score": p.risk_score,
                    "technique": p.technique,
                    "steps": p.steps,
                    "business_impact": p.business_impact,
                    "remediation": p.remediation,
                }
                for p in analysis.critical_paths
            ],
            "top_risks": [
                {"finding": r.finding, "severity": r.severity}
                for r in analysis.top_risks
            ],
            "executive_summary": analysis.executive_summary,
        }
    except ConnectionError as exc:
        logger.warning("ad_connexion_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=502, detail=f"Connexion AD échouée : {exc}") from exc
    except PermissionError as exc:
        logger.warning("ad_auth_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=401, detail=f"Authentification AD échouée : {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — erreurs LDAP/AD imprévisibles
        logger.error("ad_analyse_erreur", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await connector.close()


@router.post("/spray")
async def ad_spray(req: ADSprayRequest):
    """Password spraying (⚠️ endpoint sensible)."""
    from navmax.ad.connector import ADConfig, ADAuthMethod, ADConnector
    from navmax.ad.password_spray import PasswordSprayer, SprayConfig, SprayMode

    config = ADConfig(
        server=req.server,
        domain=req.domain,
        username=req.username,
        password=req.password,
        auth_method=ADAuthMethod.SIMPLE,
    )

    connector = ADConnector(config)
    try:
        await connector.connect()

        spray_config = SprayConfig(
            mode=SprayMode.SAFE if req.safe_mode else SprayMode.NORMAL,
            target_users=req.target_users or [],
        )

        sprayer = PasswordSprayer(connector, config=spray_config)
        if req.password_list:
            sprayer.set_wordlist(req.password_list)
        else:
            sprayer.load_default_wordlist()

        logger.info(
            "ad_spray_lancé",
            server=req.server,
            domain=req.domain,
            safe_mode=req.safe_mode,
            target_count=len(req.target_users or []),
        )

        # Spray ciblé si target_users spécifié
        session = await sprayer.spray_user_list(
            [{"username": u} for u in (req.target_users or [])]
        )

        logger.info(
            "ad_spray_terminé",
            server=req.server,
            domain=req.domain,
            attempts=session.total_attempts,
            successes=len(session.successes),
        )
        return {
            "status": "success",
            "total_attempts": session.total_attempts,
            "successes": len(session.successes),
            "successful_logins": [
                {"username": r.username, "password": r.password}
                for r in session.successes
            ],
            "duration": session.duration_seconds,
        }
    except ConnectionError as exc:
        logger.warning("ad_connexion_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=502, detail=f"Connexion AD échouée : {exc}") from exc
    except PermissionError as exc:
        logger.warning("ad_auth_échouée", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=401, detail=f"Authentification AD échouée : {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — erreurs LDAP/AD imprévisibles
        logger.error("ad_spray_erreur", server=req.server, erreur=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await connector.close()
