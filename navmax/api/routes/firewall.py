"""
API Routes — Firewall.

POST /api/v1/firewall/fortigate/rules   — Extraire règles FortiGate
POST /api/v1/firewall/stormshield/rules — Extraire règles StormShield
POST /api/v1/firewall/analyze           — Analyser règles
POST /api/v1/firewall/correlate         — Corréler AD × Firewall
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from navmax.core.logging import get_logger

router = APIRouter(prefix="/api/v1/firewall", tags=["Firewall"])
logger = get_logger(__name__)


# ── Schemas ────────────────────────────────────────────────────

class FortiGateRequest(BaseModel):
    host: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = False


class StormShieldRequest(BaseModel):
    host: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = False


class FWRulesResponse(BaseModel):
    vendor: str
    hostname: str
    model: str = ""
    version: str = ""
    rules_count: int = 0
    rules: list[dict] = []
    cve_checks: list[dict] = []


class AnalyzeRequest(BaseModel):
    vendor: str
    hostname: str
    rules: list[dict]


class CorrelateRequest(BaseModel):
    vendor: str
    hostname: str
    rules: list[dict]


# ── Routes ─────────────────────────────────────────────────────

@router.post("/fortigate/rules", response_model=FWRulesResponse)
async def fortigate_rules(req: FortiGateRequest):
    """Extrait les règles d'un FortiGate."""
    from navmax.firewall.fortigate import FortiGateConnector

    fgt = FortiGateConnector(
        host=req.host,
        api_key=req.api_key or "",
        username=req.username or "",
        password=req.password or "",
        verify_ssl=req.verify_ssl,
    )

    try:
        connected = await fgt.connect()
        if not connected:
            raise HTTPException(status_code=401, detail="Authentication failed")

        config = await fgt.get_full_config()

        logger.info(
            "fortigate_règles_extraites",
            host=req.host,
            rules_count=len(config.rules),
        )
        return {
            "vendor": "fortinet",
            "hostname": config.hostname,
            "model": config.model,
            "version": config.version,
            "rules_count": len(config.rules),
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "action": r.action,
                    "source": r.source_addresses,
                    "destination": r.destination_addresses,
                    "ports": r.destination_ports,
                    "enabled": r.enabled,
                }
                for r in config.rules[:200]  # Limite pour éviter payloads massifs
            ],
            "cve_checks": [
                {
                    "cve": c.cve_id,
                    "title": c.title,
                    "severity": c.severity,
                    "vulnerable": c.vulnerable,
                    "cvss": c.cvss_score,
                    "remediation": c.remediation,
                }
                for c in config.cve_checks
            ],
        }
    except HTTPException:
        raise
    except ConnectionError as exc:
        logger.warning("fortigate_connexion_échouée", host=req.host, erreur=str(exc))
        raise HTTPException(status_code=502, detail=f"Connexion FortiGate échouée : {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — erreurs API FortiGate imprévisibles
        logger.error("fortigate_erreur", host=req.host, erreur=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await fgt.close()


@router.post("/stormshield/rules", response_model=FWRulesResponse)
async def stormshield_rules(req: StormShieldRequest):
    """Extrait les règles d'un StormShield SNS."""
    from navmax.firewall.stormshield import StormShieldConnector

    sns = StormShieldConnector(
        host=req.host,
        api_key=req.api_key or "",
        username=req.username or "",
        password=req.password or "",
        verify_ssl=req.verify_ssl,
    )

    try:
        connected = await sns.connect()
        if not connected:
            raise HTTPException(status_code=401, detail="Authentication failed")

        config = await sns.get_full_config()

        logger.info(
            "stormshield_règles_extraites",
            host=req.host,
            rules_count=len(config.rules),
        )
        return {
            "vendor": "stormshield",
            "hostname": config.hostname,
            "model": config.model,
            "version": config.version,
            "rules_count": len(config.rules),
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "action": r.action,
                    "source": r.source_addresses,
                    "destination": r.destination_addresses,
                    "ports": r.destination_ports,
                    "enabled": r.enabled,
                }
                for r in config.rules[:200]
            ],
            "cve_checks": [
                {
                    "cve": c.cve_id,
                    "title": c.title,
                    "severity": c.severity,
                    "vulnerable": c.vulnerable,
                    "cvss": c.cvss_score,
                    "remediation": c.remediation,
                }
                for c in config.cve_checks
            ],
        }
    except HTTPException:
        raise
    except ConnectionError as exc:
        logger.warning("stormshield_connexion_échouée", host=req.host, erreur=str(exc))
        raise HTTPException(status_code=502, detail=f"Connexion StormShield échouée : {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — erreurs API StormShield imprévisibles
        logger.error("stormshield_erreur", host=req.host, erreur=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        await sns.close()


@router.post("/analyze")
async def firewall_analyze(req: AnalyzeRequest):
    """Analyse les règles firewall (shadowing, Any/Any, etc.)."""
    from navmax.firewall.base import (
        FirewallConfig, FirewallVendor, FirewallRule, RuleAction, Protocol,
    )
    from navmax.firewall.rule_analyzer import RuleAnalyzer

    vendor_map = {
        "fortinet": FirewallVendor.FORTINET,
        "stormshield": FirewallVendor.STORMSHIELD,
    }

    config = FirewallConfig(
        vendor=vendor_map.get(req.vendor, FirewallVendor.GENERIC),
        hostname=req.hostname,
        rules=[
            FirewallRule(
                id=r.get("id", str(i)),
                name=r.get("name", f"rule-{i}"),
                action=RuleAction.ALLOW if r.get("action") == "allow"
                       else RuleAction.DENY,
                source_addresses=r.get("source", []),
                destination_addresses=r.get("destination", []),
                destination_ports=r.get("ports", []),
                enabled=r.get("enabled", True),
                position=i,
            )
            for i, r in enumerate(req.rules)
        ],
    )

    analyzer = RuleAnalyzer()
    report = analyzer.analyze(config)

    return {
        "status": "success",
        "hostname": req.hostname,
        "total_rules": report.total_rules,
        "risk_score": report.risk_score,
        "findings": [
            {
                "type": f.type,
                "severity": f.severity,
                "description": f.description,
                "rules": f.rule_names,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
    }
