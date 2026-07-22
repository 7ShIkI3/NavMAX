"""Routes API Dark Triad pour le dashboard Mission Control."""

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from navmax.api.auth import require_role, get_current_user

router = APIRouter(prefix="/api/v1/dark-triad", tags=["Dark Triad"])


class MissionRequest(BaseModel):
    objective: str
    target: str = "127.0.0.1"
    persona: str = "mach"


class ScanRequest(BaseModel):
    target: str = "127.0.0.1"
    ports: str = "3333,5678,8443,8642,8083"


@router.post("/mission")
async def dark_triad_mission(req: MissionRequest, _=Depends(get_current_user)):
    """Lance une mission Dark Triad complète."""
    try:
        from navmax.dark_triad.bootstrap import run_mission
        result = await run_mission(req.objective, req.persona)
        return {
            "success": result["success"],
            "phases_completed": result["completed"],
            "phases_failed": result.get("failed", 0),
            "duration_ms": result["duration_ms"],
            "findings": [
                {"phase": p["name"], "agent": p["agent"],
                 "status": p["status"], "output": p.get("output", "")[:200],
                 "severity": "high" if "API_KEY" in (p.get("output") or "") else "med"}
                for p in result.get("phases", [])
            ],
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/scan")
async def dark_triad_scan(req: ScanRequest, _=Depends(get_current_user)):
    """Scan rapide d'une cible."""
    try:
        from navmax.dark_triad.bootstrap import init_router, bootstrap_agents
        from navmax.dark_triad.registry import AgentRegistry

        router_ai = await init_router()
        reg = AgentRegistry()
        bootstrap_agents(reg, router_ai)

        recon = reg.get("ReconAgent_mach")
        result = await recon.active_scan(req.target, req.ports)

        # Chercher credentials
        exploiter = reg.get("ExploiterAgent_mach")
        findings = []
        for port in result.get("open_ports", []):
            attempt = await exploiter._exploit_service(req.target, port, "http")
            if attempt.success:
                findings.append({
                    "port": port, "severity": "high",
                    "description": attempt.output_summary[:200],
                })

        return {
            "open_ports": result["open_ports"],
            "services": result["services"],
            "findings": findings,
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/tools")
async def dark_triad_tools(_=Depends(get_current_user)):
    """Liste les outils disponibles."""
    try:
        from navmax.dark_triad.tool_manager import ToolManager, TOOLS_CATALOG
        tm = ToolManager()
        avail = await tm.detect_all()
        return {
            "tools": [
                {"name": t.name, "category": t.category.value,
                 "available": avail.get(t.name, False),
                 "description": t.description}
                for t in TOOLS_CATALOG
            ]
        }
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/agents")
async def dark_triad_agents(_=Depends(get_current_user)):
    """Liste les agents Dark Triad."""
    return {
        "agents": [
            {"name": "ReconAgent", "type": "recon", "personalities": ["mach", "narcissism", "psychopathy"]},
            {"name": "ExploiterAgent", "type": "exploit", "personalities": ["mach", "narcissism", "psychopathy"]},
            {"name": "PostExploitAgent", "type": "post_exploit", "personalities": ["mach", "narcissism", "psychopathy"]},
            {"name": "EvaderAgent", "type": "evasion", "personalities": ["mach", "narcissism", "psychopathy"]},
            {"name": "ADSpecialistAgent", "type": "ad", "personalities": ["mach", "narcissism", "psychopathy"]},
            {"name": "PrivescAgent", "type": "privesc", "personalities": ["mach", "narcissism", "psychopathy"]},
            {"name": "JailbreakAgent", "type": "jailbreak", "personalities": ["mach", "narcissism", "psychopathy"]},
        ],
        "total": 21,
    }
