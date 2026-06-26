"""Response models Pydantic partagés pour l'API NavMAX — documentation OpenAPI."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

class HealthResponse(BaseModel):
    """Réponse de l'endpoint health check."""
    status: str = Field("ok", description="Statut du service")
    version: str = Field("0.1.0", description="Version de l'API")


# ══════════════════════════════════════════════════════════════════════════════
# AI
# ══════════════════════════════════════════════════════════════════════════════

class AIStatusResponse(BaseModel):
    """État complet du moteur IA."""
    initialized: bool
    providers: list[dict[str, Any]] = []
    active_provider: str | None = None
    active_model: str | None = None
    gpu_available: bool = False


class AIModelInfo(BaseModel):
    """Informations sur un modèle IA disponible."""
    name: str
    provider: str
    tier: str
    uncensored: bool = False
    local: bool = False
    reason: str = ""


class AIModelsResponse(BaseModel):
    """Liste des modèles IA disponibles."""
    models: list[AIModelInfo]


class AIReloadResponse(BaseModel):
    """Résultat du rechargement du moteur IA."""
    status: str = Field("reloaded", description="Statut après rechargement")
    providers_loaded: int = 0
    message: str = ""


# ══════════════════════════════════════════════════════════════════════════════
# Exploit
# ══════════════════════════════════════════════════════════════════════════════

class ExploitSearchResult(BaseModel):
    """Résultat de recherche d'exploit."""
    name: str
    title: str = ""
    platform: str = ""
    category: str = ""
    cve: str | None = None
    description: str = ""
    rank: str = ""


class ExploitSearchResponse(BaseModel):
    """Résultats de recherche d'exploits."""
    count: int
    results: list[ExploitSearchResult]


class ExploitDetailResponse(BaseModel):
    """Détail d'un exploit."""
    name: str
    description: str = ""
    platform: str = ""
    category: str = ""
    options: dict[str, Any] = {}


class ExploitRunResponse(BaseModel):
    """Résultat d'exécution d'un exploit."""
    exploit: str
    check_result: str | None = None
    check_message: str = ""
    exploit_result: str | None = None
    exploit_message: str = ""


class PayloadGenerateResponse(BaseModel):
    """Payload généré."""
    code: str
    format: str
    type: str
    encoded: str
    description: str = ""


class PayloadListResponse(BaseModel):
    """Liste des combinaisons de payloads disponibles."""
    payloads: list[dict[str, Any]]


class HandlerStartResponse(BaseModel):
    """Réponse après démarrage du handler."""
    status: str
    host: str
    port: int
    protocol: str


class HandlerStopResponse(BaseModel):
    """Réponse après arrêt du handler."""
    status: str = "stopped"


class SessionInfo(BaseModel):
    """Informations sur une session active."""
    id: str
    address: str = ""
    type: str = ""
    alive: bool = True


class HandlerStatusResponse(BaseModel):
    """État du handler."""
    status: str
    session_count: int = 0
    sessions: list[SessionInfo] = []


class SessionCommandResponse(BaseModel):
    """Résultat d'une commande sur une session."""
    session_id: str
    command: str
    output: str = ""


class SessionCloseResponse(BaseModel):
    """Résultat de fermeture d'une session."""
    closed: bool
    session_id: str


class PostModuleRunResponse(BaseModel):
    """Résultat d'exécution d'un module de post-exploitation."""
    module: str
    success: bool
    output: str = ""
    data: dict[str, Any] = {}
    error: str | None = None


class SandboxRunResponse(BaseModel):
    """Résultat d'exécution dans le sandbox."""
    success: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0
    error: str | None = None


class SandboxStatusResponse(BaseModel):
    """État du sandbox Docker."""
    docker_available: bool = False
    docker_version: str = ""
    error: str | None = None


# ══════════════════════════════════════════════════════════════════════════════
# Active Directory
# ══════════════════════════════════════════════════════════════════════════════

class ADEnumerateResponse(BaseModel):
    """Résumé de l'énumération Active Directory."""
    status: str
    domain: str
    users: int = 0
    groups: int = 0
    computers: int = 0
    ous: int = 0
    gpos: int = 0
    trusts: int = 0
    privileged_users: int = 0
    kerberoastable_users: int = 0
    summary: dict[str, Any] = {}


class ADFinding(BaseModel):
    """Finding de vulnérabilité AD."""
    title: str
    severity: str
    category: str
    affected_count: int = 0
    remediation: str = ""


class ADScanResponse(BaseModel):
    """Rapport de scan de vulnérabilités Active Directory."""
    status: str
    domain: str
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    findings: list[ADFinding] = []


class ADCrticalPath(BaseModel):
    """Chemin d'attaque critique."""
    name: str
    source: str
    target: str
    risk_score: float = 0.0
    technique: str = ""
    steps: list[str] = []
    business_impact: str = ""
    remediation: str = ""


class ADTopRisk(BaseModel):
    """Risque prioritaire."""
    finding: str
    severity: str


class ADAnalyzeResponse(BaseModel):
    """Analyse des chemins d'attaque AD."""
    status: str
    domain: str
    overall_risk: str = ""
    exposed_users: int = 0
    kerberoastable_paths: bool = False
    critical_paths: list[ADCrticalPath] = []
    top_risks: list[ADTopRisk] = []
    executive_summary: str = ""


class ADSuccessfulLogin(BaseModel):
    """Login réussi lors du password spraying."""
    username: str
    password: str


class ADSprayResponse(BaseModel):
    """Résultat du password spraying."""
    status: str
    total_attempts: int = 0
    successes: int = 0
    successful_logins: list[ADSuccessfulLogin] = []
    duration: float = 0.0


# ══════════════════════════════════════════════════════════════════════════════
# Nuclei
# ══════════════════════════════════════════════════════════════════════════════

class NucleiFinding(BaseModel):
    """Vulnérabilité détectée par nuclei."""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str = ""
    description: str = ""
    cvss_score: float | None = None
    cve_ids: list[str] = []
    reference_urls: list[str] = []
    extracted_results: list[str] = []


class NucleiScanResponse(BaseModel):
    """Résultat d'un scan nuclei."""
    target: str
    findings_count: int = 0
    findings: list[NucleiFinding] = []


class NucleiUpdateTemplatesResponse(BaseModel):
    """Résultat de mise à jour des templates nuclei."""
    status: str
    message: str


class NucleiStatusResponse(BaseModel):
    """État de l'installation nuclei."""
    installed: bool = False
    templates_available: bool = False
    binary_path: str | None = None


# ══════════════════════════════════════════════════════════════════════════════
# OSINT
# ══════════════════════════════════════════════════════════════════════════════

class DNSRecord(BaseModel):
    """Enregistrement DNS."""
    type: str
    name: str
    value: str
    ttl: int = 0


class DNSLookupResponse(BaseModel):
    """Résultat de résolution DNS."""
    domain: str
    count: int = 0
    records: list[DNSRecord] = []


class WhoisLookupResponse(BaseModel):
    """Informations WHOIS d'un domaine."""
    domain: str
    registrar: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    name_servers: list[str] = []
    registrant_name: str | None = None
    registrant_org: str | None = None
    registrant_email: str | None = None
    registrant_country: str | None = None
    error: str | None = None


class SSLLookupResponse(BaseModel):
    """Informations de certificat SSL."""
    host: str
    port: int = 443
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = []
    fingerprint_sha256: str = ""
    is_valid: bool = False
    days_remaining: int = 0
    error: str | None = None


class WebAnalyzeResponse(BaseModel):
    """Analyse d'une page web."""
    url: str
    status_code: int | None = None
    title: str = ""
    server: str = ""
    technologies: list[str] = []
    emails_found: list[str] = []
    links_external: list[str] = []
    social_links: dict[str, str] = {}
    error: str | None = None


class InvestigateResponse(BaseModel):
    """Résultat d'investigation OSINT complète."""
    target: str
    type: str
    nodes: int = 0
    edges: int = 0
    log: list[str] = []
    graph: dict[str, Any] = {}


class TransformInfo(BaseModel):
    """Information sur un transform OSINT."""
    name: str
    input_type: str
    description: str = ""


class ListTransformsResponse(BaseModel):
    """Liste des transforms OSINT disponibles."""
    transforms: list[TransformInfo]


# ══════════════════════════════════════════════════════════════════════════════
# Proxy
# ══════════════════════════════════════════════════════════════════════════════

class ProxyStartResponse(BaseModel):
    """Réponse après démarrage du proxy."""
    status: str
    host: str = ""
    port: int = 0


class ProxyStopResponse(BaseModel):
    """Réponse après arrêt du proxy."""
    status: str


class ProxyStatusResponse(BaseModel):
    """État du proxy."""
    running: bool = False
    host: str | None = None
    port: int | None = None
    flow_count: int = 0
    intercept_enabled: bool = False
    pending_count: int = 0


class InterceptToggleResponse(BaseModel):
    """État de l'interception après bascule."""
    intercept_enabled: bool


class FlowItem(BaseModel):
    """Flux HTTP intercepté."""
    id: str
    method: str
    host: str = ""
    port: int = 0
    path: str = ""
    request_headers: dict[str, str] = {}
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    status: str


class FlowListResponse(BaseModel):
    """Liste des flux interceptés."""
    data: list[FlowItem]
    count: int = 0


class FlowDecisionResponse(BaseModel):
    """Résultat de la décision sur un flux."""
    status: str
    flow_id: str
    action: str


class VulnerabilityInfo(BaseModel):
    """Vulnérabilité web détectée."""
    name: str
    severity: str
    parameter: str | None = None
    payload: str | None = None
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str | None = None


class ScanURLResponse(BaseModel):
    """Résultat du scan d'URL."""
    url: str
    vulnerability_count: int = 0
    vulnerabilities: list[VulnerabilityInfo] = []


class AnomalyInfo(BaseModel):
    """Anomalie détectée par le fuzzer."""
    injection_point: str
    parameter: str
    payload: str
    category: str
    anomaly: str
    evidence: str


class FuzzResponse(BaseModel):
    """Résultat du fuzzing d'URL."""
    url: str
    total_tests: int = 0
    anomaly_count: int = 0
    duration_ms: float = 0.0
    anomalies: list[AnomalyInfo] = []


class ReplayResponse(BaseModel):
    """Résultat du replay de requête."""
    status: int | None = None
    headers: dict[str, str] = {}
    body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None


class ReplayHistoryItem(BaseModel):
    """Élément de l'historique des replays."""
    request: dict[str, str] = {}
    response: dict[str, Any] = {}
    timestamp: str = ""


class ReplayHistoryResponse(BaseModel):
    """Historique des replays."""
    data: list[ReplayHistoryItem]


# ══════════════════════════════════════════════════════════════════════════════
# Firewall
# ══════════════════════════════════════════════════════════════════════════════

class FWRuleInfo(BaseModel):
    """Règle firewall simplifiée."""
    id: str
    name: str = ""
    action: str = ""
    source: list[str] = []
    destination: list[str] = []
    ports: list[str] = []
    enabled: bool = True


class FWCVECheck(BaseModel):
    """Vérification CVE sur le firewall."""
    cve: str
    title: str = ""
    severity: str = ""
    vulnerable: bool = False
    cvss: float = 0.0
    remediation: str = ""


class FWRulesResponse(BaseModel):
    """Règles extraites d'un firewall."""
    vendor: str
    hostname: str
    model: str = ""
    version: str = ""
    rules_count: int = 0
    rules: list[FWRuleInfo] = []
    cve_checks: list[FWCVECheck] = []


class FWFinding(BaseModel):
    """Finding d'analyse de règles firewall."""
    type: str
    severity: str
    description: str
    rules: list[str] = []
    recommendation: str = ""


class FirewallAnalyzeResponse(BaseModel):
    """Rapport d'analyse des règles firewall."""
    status: str
    hostname: str
    total_rules: int = 0
    risk_score: float = 0.0
    findings: list[FWFinding] = []


# ══════════════════════════════════════════════════════════════════════════════
# Workspaces
# ══════════════════════════════════════════════════════════════════════════════

class WorkspaceCreateResponse(BaseModel):
    """Workspace créé."""
    id: str
    name: str
    description: str = ""


class WorkspaceItem(BaseModel):
    """Élément de liste de workspaces."""
    id: str
    name: str
    description: str = ""
    target_count: int = 0
    created_at: str | None = None


class WorkspaceListResponse(BaseModel):
    """Liste des workspaces."""
    count: int = 0
    workspaces: list[WorkspaceItem]


class WorkspaceDetailResponse(BaseModel):
    """Détail d'un workspace."""
    id: str
    name: str
    description: str = ""
    stats: dict[str, Any] = {}


class WorkspaceUpdateResponse(BaseModel):
    """Workspace mis à jour."""
    id: str
    name: str
    description: str = ""


class WorkspaceDeleteResponse(BaseModel):
    """Confirmation de suppression."""
    deleted: bool


class TargetAssignResponse(BaseModel):
    """Confirmation d'association."""
    associated: bool


class TargetRemoveResponse(BaseModel):
    """Confirmation de désassociation."""
    disassociated: bool


class WorkspaceTargetItem(BaseModel):
    """Cible dans un workspace."""
    id: str
    name: str
    address: str
    kind: str


class WorkspaceTargetListResponse(BaseModel):
    """Liste des cibles d'un workspace."""
    count: int = 0
    targets: list[WorkspaceTargetItem]
