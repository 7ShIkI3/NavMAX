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

from navmax.db.session import get_session

router = APIRouter(prefix="/api/v1/ad", tags=["Active Directory"])


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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
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

        # Spray ciblé si target_users spécifié
        session = await sprayer.spray_user_list(
            [{"username": u} for u in (req.target_users or [])]
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await connector.close()
