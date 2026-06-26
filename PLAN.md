# PLAN D'IMPLÉMENTATION — NavMAX v0.7.0 (7 RFCs)

> Généré le 2026-06-26 — Basé sur l'analyse des 7 RFCs et de la codebase existante.

---

## 1. TRIAGE & PRIORISATION RÉELLE

### Matrice Effort vs Impact

| RFC | Priorité User | Impact réel | Effort réel | Ratio I/E | Priorité finale |
|-----|:-:|:-:|:-:|:-:|:-:|
| **RFC-001** masscan | P1 | 9/10 | 1-2j | **4.5** | **🥇 P1** |
| **RFC-007** Semgrep | P2 | 8/10 | 1.5-2j | **4.0** | **🥇 P1** |
| **RFC-002** nxc/netexec | P2 | 9/10 | 3-4j | **2.6** | **🥈 P2** |
| **RFC-006** EscalateGPT | P2 | 7/10 | 1.5-2j | **4.0** | **🥇 P1** |
| **RFC-004** RAPTOR | P2 | 8/10 | 2-3j | **3.2** | **🥈 P2** |
| **RFC-003** bettercap | P3 | 8/10 | 4-5j | **1.8** | **🥉 P3** |
| **RFC-005** Basilisk | P3 | 6/10 | 1.5-2j | **3.5** | **🥈 P2** |

> **Note** : EscalateGPT et Basilisk remontent car leur effort est très faible pour un impact significatif. bettercap reste P3 car effort élevé + dépendances matérielles (monitor mode).

---

## 2. ARBRE DES DÉPENDANCES

```
                    ┌──────────────────────────┐
                    │     PHASE 1 (P1)         │
                    │  Semaine 1 — Jour 1-3    │
                    │                          │
                    │  ┌──────────┐ ┌────────┐ │
                    │  │ RFC-001  │ │ RFC-007│ │
                    │  │ masscan  │ │ Semgrep│ │
                    │  └────┬─────┘ └────┬───┘ │
                    └───────┼─────────────┼─────┘
                            │             │
                    ┌───────┴─────────────┴─────────────────┐
                    │         PHASE 2 (P1/P2)                │
                    │   Semaine 1-2 — Jour 3-7               │
                    │                                        │
                    │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
                    │  │ RFC-002  │ │ RFC-006  │ │RFC-004 │ │
                    │  │ nxc/netex│ │EscalGPT  │ │ RAPTOR │ │
                    │  │ (ad/)    │ │ (cloud/) │ │ (ai/)  │ │
                    │  └──────────┘ └──────────┘ └────────┘ │
                    └───────────────────┬────────────────────┘
                                        │
                    ┌───────────────────┴────────────────────┐
                    │         PHASE 3 (P2/P3)                │
                    │     Semaine 3 — Jour 8-12              │
                    │                                        │
                    │  ┌──────────┐ ┌──────────┐             │
                    │  │ RFC-003  │ │ RFC-005  │             │
                    │  │ bettercap│ │ Basilisk │             │
                    │  │(wireless)│ │(ai/redtm)│             │
                    │  └──────────┘ └──────────┘             │
                    └────────────────────────────────────────┘
```

### Parallélisation maximale

| Phase | RFCs parallélisables | Ressources |
|-------|---------------------|------------|
| **1a** | RFC-001 (masscan) | 1 dev — `scanner/` |
| **1b** | RFC-007 (Semgrep) | 1 dev — `scanner/` |
| **2a** | RFC-002 (nxc) | 1 dev — `ad/` |
| **2b** | RFC-006 (EscalateGPT) | 1 dev — `cloud/` |
| **2c** | RFC-004 (RAPTOR) | 1 dev — `ai/` |
| **3a** | RFC-003 (bettercap) | 1 dev — `wireless/` |
| **3b** | RFC-005 (Basilisk) | 1 dev — `ai/redteam/` |

**→ 2 devs peuvent finir les 7 RFCs en ~10 jours ouvrés.**
**→ 1 dev seul : ~15 jours ouvrés (3 semaines).**

---

## 3. PHASE 1 — FOUNDATIONS (P1)

### 3.1 RFC-001 : Masscan (Scanner de ports ultra-rapide)

**Module** : `scanner/` — **Effort** : 1-2 jours — **Dépendances** : binaire `masscan`

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/scanner/masscan_scanner.py` | **Créer** | Base → Connector → Analyzer |
| `navmax/scanner/__init__.py` | **Modifier** | Exporter `MasscanScanner`, `MasscanResult` |
| `navmax/scanner/engine.py` | **Modifier** | Ajouter `run_masscan_scan()` |
| `navmax/cli.py` | **Modifier** | Ajouter commande `navmax masscan` |
| `navmax/api/schemas.py` | **Modifier** | `MasscanRequest`, `MasscanResponse` |
| `navmax/api/routes/scans.py` | **Modifier** | `POST /api/v1/scans/masscan` |
| `tests/test_masscan_scanner.py` | **Créer** | Tests unitaires + intégration |
| `docs/masscan.md` | **Créer** | Documentation utilisateur |

#### Pattern détaillé

```
navmax/scanner/masscan_scanner.py
├── MasscanPort          (dataclass)   ← Base models
├── MasscanResult        (dataclass)   ← Base models  
├── MasscanScanner       (class)       ← Connector (subprocess async)
│   ├── _find_binary()                 → shutil.which("masscan")
│   ├── scan(targets, ports, rate...)  → subprocess async
│   ├── _parse_json_output()           → Analyzer (JSON parser)
│   ├── _parse_grepable_output()       → Analyzer (grepable parser)
│   ├── _validate_rate()               → Security validation
│   └── _adapt_rate()                  → Auto réduction si perte > 10%
└── quick_masscan_scan()   (fonction)   → Convenience wrapper
```

#### Points d'attention ⚠️

- **Sécurité** : masscan peut saturer la bande passante — `rate` plafonné à 100 000 par défaut
- **Root requis ?** : masscan nécessite `CAP_NET_RAW` ou root — détection + fallback
- **Parsing** : JSON output de masscan change selon la version — tests de compatibilité
- **Intégration engine.py** : ne pas casser l'existant, ajouter en option
- **Binaire optionnel** : si masscan absent, message clair + suggestion d'install

#### Tests

| # | Test | Type | fichier |
|---|------|------|---------|
| T1 | `test_masscan_binary_found` | Unitaire | Détection du binaire |
| T2 | `test_masscan_binary_not_found` | Unitaire | Fallback si absent |
| T3 | `test_masscan_parse_json_output` | Unitaire | Parse JSON type |
| T4 | `test_masscan_parse_grepable` | Unitaire | Parse grepable |
| T5 | `test_masscan_rate_validation` | Unitaire | Rate min(100)/max(100000) |
| T6 | `test_masscan_exclude_filter` | Unitaire | --exclude param |
| T7 | `test_masscan_target_formats` | Unitaire | CIDR, IP range, list |
| T8 | `test_masscan_adapt_rate` | Unitaire | Auto-reduce logic |
| T9 | `test_masscan_integration_localhost` | Intégration | Scan réel localhost |
| T10 | `test_masscan_api_endpoint` | Intégration | POST /masscan |

---

### 3.2 RFC-007 : Semgrep (SAST multi-langage)

**Module** : `scanner/` — **Effort** : 1.5-2 jours — **Dépendances** : binaire `semgrep` + pip `semgrep`

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/scanner/semgrep_wrapper.py` | **Créer** | Base → Connector → Analyzer |
| `navmax/scanner/semgrep_rules/` | **Créer** | Dossier règles personnalisées |
| `navmax/scanner/semgrep_rules/__init__.py` | **Créer** | Package marker |
| `navmax/scanner/__init__.py` | **Modifier** | Exporter `SemgrepScanner`, `SemgrepFinding` |
| `navmax/scanner/engine.py` | **Modifier** | Ajouter `run_semgrep_scan()` |
| `navmax/cli.py` | **Modifier** | Ajouter commande `navmax semgrep` |
| `navmax/api/schemas.py` | **Modifier** | `SemgrepRequest`, `SemgrepResponse` |
| `navmax/api/routes/scans.py` | **Modifier** | `POST /api/v1/scans/semgrep` |
| `tests/test_semgrep_wrapper.py` | **Créer** | Tests |
| `docs/semgrep.md` | **Créer** | Documentation |

#### Pattern détaillé

```
navmax/scanner/semgrep_wrapper.py
├── SemgrepSeverity       (enum)       ← Base: ERROR, WARNING, INFO
├── SemgrepFinding        (pydantic)   ← Base: path, line, message, severity
├── SemgrepResult         (pydantic)   ← Base: findings[], summary stats
├── SemgrepScanner        (class)      ← Connector
│   ├── _find_binary()                 → shutil.which("semgrep") ou pip import
│   ├── scan(path, rules, lang...)     → subprocess async semgrep --json
│   ├── _parse_sarif_output()          → Analyzer (SARIF JSON parser)
│   ├── _find_in_path()                → Recherche des règles
│   └── _categorize_findings()         → Categorization par CWE/OWASP
├── BUILTIN_RULES                      → Règles custom pour NavMAX
└── quick_semgrep_scan()   (fonction)  → Convenience
```

#### Règles personnalisées à inclure

| Règle | Cible | Description |
|-------|-------|-------------|
| `navmax-insecure-crypto` | Python | Détection chiffrement faible (DES, MD4, MD5) |
| `navmax-command-injection` | Python/shell | `os.system()`, `subprocess(shell=True)` |
| `navmax-sql-injection` | Python/SQL | Requêtes SQL non paramétrées |
| `navmax-hardcoded-creds` | Tous | Mots de passe/AK/SK en dur |
| `navmax-path-traversal` | Python | Path traversal non sanitized |

#### Points d'attention ⚠️

- **Performance** : semgrep peut être lent sur de gros dépôts — timeout + streaming progress
- **Installation** : préférer `pip install semgrep` (Python pur) plutôt que binaire
- **SARIF output** : utiliser `--sarif` pour output standardisé (intégrable avec GitHub)
- **Règles personnalisées** : les règles NavMAX doivent être versionnées dans le repo
- **Gros fichiers** : ignorer `node_modules/`, `vendor/`, `dist/` par défaut

#### Tests

| # | Test | Type | Description |
|---|------|------|-------------|
| T1 | `test_semgrep_binary_found` | Unitaire | Détection binaire/pip |
| T2 | `test_semgrep_parse_sarif` | Unitaire | Parse output SARIF |
| T3 | `test_semgrep_scan_python_file` | Unitaire | Scan fichier Python simple |
| T4 | `test_semgrep_finding_model` | Unitaire | Validation modèle Pydantic |
| T5 | `test_semgrep_builtin_rules` | Unitaire | Règles NavMAX chargées |
| T6 | `test_semgrep_empty_result` | Unitaire | Scan sans vulnérabilités |
| T7 | `test_semgrep_language_filter` | Unitaire | Filtre par langage |
| T8 | `test_semgrep_integration` | Intégration | Scan d'un dossier test |

---

## 4. PHASE 2 — EXPLOITATION & IA (P1/P2)

### 4.1 RFC-002 : NetExec/nxc (Exploitation AD multi-protocole)

**Module** : `ad/` — **Effort** : 3-4 jours — **Dépendances** : `pipx install netexec`, `impacket` (déjà présent)

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/ad/netexec_wrapper.py` | **Créer** | Wrapper principal |
| `navmax/ad/netexec_parser.py` | **Créer** | Parsing des outputs textes |
| `navmax/ad/__init__.py` | **Modifier** | Exporter les nouvelles classes |
| `navmax/cli.py` | **Modifier** | Ajouter commande `navmax netexec` |
| `navmax/api/schemas.py` | **Modifier** | Toutes les request/response models |
| `navmax/api/routes/ad.py` | **Modifier** | 5 nouveaux endpoints NetExec |
| `tests/test_netexec_wrapper.py` | **Créer** | Tests unitaires |
| `tests/test_netexec_parser.py` | **Créer** | Tests parsing |
| `docs/netexec.md` | **Créer** | Documentation |

#### Pattern détaillé

```
navmax/ad/netexec_wrapper.py
├── NetExecProtocol       (enum)       ← Base: SMB, WINRM, LDAP, MSSQL, SSH, RDP, FTP
├── NetExecTarget         (dataclass)  ← Base: host, protocol, port
├── NetExecCredential     (dataclass)  ← Base: username, password, nt_hash, domain
├── NetExecResult         (dataclass)  ← Base: status, output, shares, users...
├── NetExecWrapper        (class)      ← Connector principal
│   ├── _find_binary()                 → shutil.which("netexec") or "nxc"
│   ├── smb_enum(targets, creds...)    → nxc smb <target> -u ... -p ...
│   ├── winrm_exec(target, creds, cmd) → nxc winrm <target> -u ... -X <cmd>
│   ├── ldap_enum(target, creds...)    → nxc ldap <target> --kerberoast --asrep ...
│   ├── mssql_enum(target, creds...)   → nxc mssql <target> -u ... -p ...
│   ├── check_vulnerability(target, vuln) → nxc smb <target> -M zerologon
│   ├── pass_the_hash(target, hash...) → nxc smb <target> -H <hash>
│   ├── _build_base_args()             → Construction args communs
│   └── _run_async(target..., method)  → subprocess asyncio

navmax/ad/netexec_parser.py
├── parse_smb_output(stdout)           → NetExecResult
├── parse_ldap_output(stdout)          → NetExecResult
├── parse_winrm_output(stdout)         → NetExecResult
├── parse_vuln_output(stdout)          → NetExecResult
├── extract_pwned_status(line)         → Détection "Pwn3d!"
├── extract_shares(lines)              → Listing SMB shares
├── extract_kerberoast_hashes(lines)   → Extraction hashes
└── extract_sam_dump(lines)            → Extraction SAM hashes
```

#### CLI Commands

```
navmax netexec smb <target> -u <user> -p <pass> -d <domain>
navmax netexec ldap <target> -u <user> -p <pass> --kerberoast
navmax netexec winrm <target> -u <user> -p <pass> -c "whoami"
navmax netexec pth <target> -u <user> -H <hash> -d <domain>
navmax netexec vuln <target> -u <user> -p <pass> --check zerologon
```

#### API Endpoints

```
POST /api/v1/ad/netexec/smb     → SMB Enum
POST /api/v1/ad/netexec/ldap    → LDAP Enum avancé
POST /api/v1/ad/netexec/winrm   → Exécution commande
POST /api/v1/ad/netexec/pth     → Pass-the-Hash
POST /api/v1/ad/netexec/vuln    → Check vulnérabilité
GET  /api/v1/ad/netexec/modules → Liste modules disponibles
```

#### Points d'attention ⚠️

- **Parsing texte** : nxc output est textuel, pas structuré — parsing fragile, multiples patterns
- **Permutations credentials** : gérer plusieurs users/pass en batch
- **Timeouts longs** : certains scans (SAM dump) prennent > 5 min
- **Binaire renommé** : supporter `netexec` ET `nxc` (transition CME → nxc)
- **Fallback** : si nxc absent, proposer `pipx install netexec` avec message clair

#### Tests

| # | Test | Description |
|---|-------|-------------|
| T1 | `test_netexec_binary_found` | Détection nxc/netexec |
| T2 | `test_netexec_parse_smb_enum` | Parse sortie SMB type |
| T3 | `test_netexec_parse_ldap_enum` | Parse sortie LDAP type |
| T4 | `test_netexec_parse_pwned` | Détection "Pwn3d!" |
| T5 | `test_netexec_parse_vuln` | Parse ZeroLogon/PrintNightmare |
| T6 | `test_netexec_credential_build` | Construction args -u/-p/-H/-d |
| T7 | `test_netexec_build_args_smb` | Args SMB corrects |
| T8 | `test_netexec_parse_kerberoast` | Extraction hashes |
| T9 | `test_netexec_parse_shares` | Listing partages |
| T10 | `test_netexec_pth_command` | Pass-the-Hash args |

---

### 4.2 RFC-006 : EscalateGPT (Cloud IAM Privesc)

**Module** : `cloud/` — **Effort** : 1.5-2 jours — **Dépendances** : `pip install escalategpt` (optionnel)

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/cloud/escalate_gpt.py` | **Créer** | Pont LLM IAM privesc |
| `navmax/cloud/iam_analyzer.py` | **Modifier** | Enrichir l'analyzeur existant |
| `navmax/cloud/__init__.py` | **Modifier** | Exporter nouvelles classes |
| `navmax/cli.py` | **Modifier** | `navmax cloud iam-analyze [--ai]` |
| `navmax/api/routes/cloud.py` | **Créer** (ou enrichir) | Nouveaux endpoints |
| `tests/test_escalate_gpt.py` | **Créer** | Tests |
| `docs/escalate_gpt.md` | **Créer** | Documentation |

#### Pattern détaillé

```
navmax/cloud/escalate_gpt.py
├── EscalateGPTConfig     (pydantic)   ← Config OpenAI/Anthropic/Ollama
├── PrivescPath           (pydantic)   ← Base: resource, technique, risk, mitre_id
├── PrivescAnalysis       (pydantic)   ← Base: paths[], summary, recommendations
├── EscalateGPTBridge     (class)      ← Connector IA
│   ├── __init__(provider, model)      → Utilise AIEngine existant
│   ├── analyze_policy(policy_doc)     → Prompt LLM: trouve chemins privesc
│   ├── analyze_aws_iam(iam_json)      → Analyse politique IAM AWS
│   ├── analyze_azure_iam(role_json)   → Analyse rôle Azure
│   ├── suggest_fixes(path)            → Propositions de correction
│   └── _build_prompt(context)         → Template prompt structuré
└── quick_iam_analysis(provider, data)  → Fonction convenience
```

#### Points d'attention ⚠️

- **LLM optionnel** : l'analyse IAM doit fonctionner aussi sans LLM (mode règles)
- **Coût API** : limiter les appels LLM — cache des résultats, rate limiting
- **Context Window** : les politiques IAM peuvent être longues — chunking si besoin
- **Provider agnostic** : utiliser `AIEngine` existant (support OpenAI, Ollama, etc.)

#### Tests

| # | Test | Description |
|---|-------|-------------|
| T1 | `test_escalate_gpt_parse_policy` | Parse politique IAM AWS |
| T2 | `test_escalate_gpt_privesc_path` | Détection chemin privesc |
| T3 | `test_escalate_gpt_no_llm_fallback` | Fallback sans LLM |
| T4 | `test_escalate_gpt_model_validation` | Validation Pydantic |
| T5 | `test_escalate_gpt_azure_roles` | Analyse rôles Azure |

---

### 4.3 RFC-004 : RAPTOR (Agent Autonome Offensif)

**Module** : `ai/` + nouveau `raptor/`  — **Effort** : 2-3 jours — **Dépendances** : Git, API Anthropic/OpenAI

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/ai/raptor_bridge.py` | **Créer** | Pont RAPTOR ↔ NavMAX |
| `navmax/ai/raptor_skills/__init__.py` | **Créer** | Sous-agents skills |
| `navmax/ai/raptor_skills/recon_agent.py` | **Créer** | Agent reconnaissance |
| `navmax/ai/raptor_skills/exploit_agent.py` | **Créer** | Agent exploitation |
| `navmax/ai/raptor_skills/patch_agent.py` | **Créer** | Agent correction |
| `navmax/ai/__init__.py` | **Modifier** | Exporter bridge |
| `navmax/cli.py` | **Modifier** | `navmax raptor run` |
| `navmax/api/routes/ai.py` | **Modifier** | Endpoints RAPTOR |
| `tests/test_raptor_bridge.py` | **Créer** | Tests |
| `docs/raptor.md` | **Créer** | Documentation |

#### Pattern détaillé

```
navmax/ai/raptor_bridge.py
├── RaptorSkill            (enum)      ← RECON, EXPLOIT, PATCH
├── RaptorMission          (dataclass) ← Base: target, skills[], options
├── RaptorResult           (dataclass) ← Base: findings[], patches[], report
├── RaptorBridge           (class)     ← Connector RAPTOR
│   ├── __init__(ai_engine)           → Utilise AIEngine existant
│   ├── run_mission(target, skills)   → Orchestre les sous-agents
│   ├── _run_recon(mission)           → Agent recon
│   ├── _run_exploit(findings)        → Agent exploit
│   ├── _run_patch(exploits)          → Agent patch
│   └── _generate_report(results)     → Rapport final

navmax/ai/raptor_skills/
├── recon_agent.py          → Prompt: "Identify attack surface..."
├── exploit_agent.py        → Prompt: "Generate exploit for..."
└── patch_agent.py          → Prompt: "Create patch for..."
```

#### Points d'attention ⚠️

- **Coût LLM** : appels multiples (recon → exploit → patch) — budget tracking
- **Sécurité** : agent exécute du code — sandbox Docker obligatoire
- **Timeout** : missions longues (> 10 min) — streaming SSE + Celery background
- **Version RAPTOR** : spécifier tag git, pas `main` (breaking changes possibles)

#### Tests

| # | Test | Description |
|---|-------|-------------|
| T1 | `test_raptor_bridge_init` | Initialisation bridge |
| T2 | `test_raptor_mission_model` | Validation mission |
| T3 | `test_raptor_skills_load` | Chargement skills |
| T4 | `test_raptor_result_model` | Validation résultat |
| T5 | `test_raptor_bridge_no_llm` | Comportement sans LLM |

---

## 5. PHASE 3 — WIFI & ADVANCED (P2/P3)

### 5.1 RFC-003 : Bettercap (MITM WiFi & Réseau)

**Module** : `wireless/` — **Effort** : 4-5 jours — **Dépendances** : binaire `bettercap` (≥ 2.33), `aiohttp` (déjà présent)

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/wireless/bettercap_wrapper.py` | **Créer** | API REST wrapper |
| `navmax/wireless/bettercap_runner.py` | **Créer** | Script bettercap auto |
| `navmax/wireless/__init__.py` | **Modifier** | Exporter nouvelles classes |
| `navmax/cli.py` | **Modifier** | Groupe `navmax wifi` |
| `navmax/api/routes/wireless.py` | **Créer** | Routes API bettercap |
| `navmax/api/schemas.py` | **Modifier** | Tous les modèles bettercap |
| `navmax/api/routes/__init__.py` | **Modifier** | Ajouter `wireless` |
| `tests/test_bettercap_wrapper.py` | **Créer** | Tests unitaires |
| `docs/bettercap.md` | **Créer** | Documentation |

#### Pattern détaillé

```
navmax/wireless/bettercap_wrapper.py
├── BettercapModule        (enum)      ← ARP_SPOOFER, DNS_SPOOFER, NET_SNIFFER...
├── BettercapSession       (dataclass) ← Session bettercap active
├── Credential             (dataclass) ← Credential capturé
├── BettercapWrapper       (class)     ← Connector API REST
│   ├── __init__(api_host, api_port)   → http://127.0.0.1:8081/api
│   ├── start(interface, headless)     → GET /api/session + POST /api/session
│   ├── stop()                         → POST /api/session/stop
│   ├── arp_spoof(target, gateway)    → POST /api/module/arp.spoof
│   ├── dns_spoof(hosts)              → POST /api/module/dns.spoof
│   ├── net_sniff(protocols)          → POST /api/module/net.sniff
│   ├── http_proxy(port, ssl_strip)   → POST /api/module/http.proxy
│   ├── wifi_deauth(bssid, channel)   → POST /api/module/wifi.deauth
│   ├── wifi_ap(ssid, channel, auth)  → POST /api/module/wifi.ap
│   ├── wifi_beacon_flood(ssids)      → POST /api/module/wifi.beacon
│   ├── wifi_captive_portal(ssid)     → POST /api/module/caplet
│   ├── get_events(since, types)      → GET /api/events
│   └── get_stats()                   → GET /api/session

navmax/wireless/bettercap_runner.py
├── generate_script(password)         → Génère script bettercap .cap
├── BETTERCAP_SCRIPT                  → Template de démarrage headless
└── start_bettercap_process(iface)    → subprocess manage lifecycle
```

#### CLI Commands

```
navmax wifi start <interface>
navmax wifi stop
navmax wifi mitm <target> <gateway> [--sniff]
navmax wifi deauth [--bssid XX:XX] [--channel N]
navmax wifi ap <ssid> [--password P] [--evil-twin]
navmax wifi portal <ssid> [--template FILE]
navmax wifi beacon-flood [--ssids LIST] [--rate N]
navmax wifi events
navmax wifi stats
navmax wifi credentials
```

#### API Endpoints (nouveau fichier)

```
POST  /api/v1/wireless/bettercap/start
POST  /api/v1/wireless/bettercap/stop
POST  /api/v1/wireless/bettercap/arp-spoof
POST  /api/v1/wireless/bettercap/dns-spoof
POST  /api/v1/wireless/bettercap/wifi/deauth
POST  /api/v1/wireless/bettercap/wifi/ap
POST  /api/v1/wireless/bettercap/wifi/portal
GET   /api/v1/wireless/bettercap/events
GET   /api/v1/wireless/bettercap/stats
GET   /api/v1/wireless/bettercap/credentials
```

#### Points d'attention ⚠️

- **Root requis** : bettercap nécessite des privilèges root pour les attaques WiFi
- **API REST** : bettercap expose API REST sur 127.0.0.1:8081 (auth basique)
- **Lifecycle** : bien gérer start/stop, process zombie, port déjà utilisé
- **Monitor mode** : détection automatique des interfaces en mode monitor
- **Fallback** : si mieuxcap absent, proposer `sudo snap install bettercap`
- **Compatibilité** : bettercap ≥ 2.33 (API stable depuis cette version)

#### Tests

| # | Test | Description |
|---|-------|-------------|
| T1 | `test_bettercap_binary_found` | Détection binaire |
| T2 | `test_bettercap_api_health` | Vérification API REST |
| T3 | `test_bettercap_parse_credentials` | Parse credentials |
| T4 | `test_bettercap_parse_events` | Parse events JSON |
| T5 | `test_bettercap_arp_spoof_cmd` | Construction ARP spoof |
| T6 | `test_bettercap_dns_spoof_cmd` | Construction DNS spoof |
| T7 | `test_bettercap_session_lifecycle` | Start/stop cycle |
| T8 | `test_bettercap_wifi_deauth_cmd` | Args déauth |
| T9 | `test_bettercap_wifi_ap_cmd` | Args AP |
| T10 | `test_bettercap_runner_script` | Génération script .cap |

---

### 5.2 RFC-005 : Basilisk (AI Red Teaming pour LLMs)

**Module** : `ai/redteam/` — **Effort** : 1.5-2 jours — **Dépendances** : Git clone, Python packages

#### Fichiers à créer/modifier

| Fichier | Action | Rôle |
|---------|--------|------|
| `navmax/ai/redteam/__init__.py` | **Créer** | Package marker |
| `navmax/ai/redteam/basilisk_wrapper.py` | **Créer** | Connector Basilisk |
| `navmax/ai/redteam/campaigns/__init__.py` | **Créer** | Campagnes prédéfinies |
| `navmax/ai/redteam/campaigns/owasp_top10.json` | **Créer** | OWASP LLM Top 10 |
| `navmax/ai/__init__.py` | **Modifier** | Exporter redteam |
| `navmax/cli.py` | **Modifier** | `navmax redteam run` |
| `navmax/api/routes/ai.py` | **Modifier** | Endpoints Basilisk |
| `tests/test_basilisk_wrapper.py` | **Créer** | Tests |
| `docs/basilisk.md` | **Créer** | Documentation |

#### Pattern détaillé

```
navmax/ai/redteam/basilisk_wrapper.py
├── BasiliskCampaign       (pydantic)  ← Base: nom, modules[], target_llm
├── BasiliskAttack          (pydantic)  ← Base: technique, prompt, response, score
├── BasiliskReport          (pydantic)  ← Base: attacks[], owasp_map, summary
├── BasiliskWrapper         (class)     ← Connector
│   ├── __init__(basilisk_path)        → Path vers repo basilisk cloné
│   ├── install_if_missing()           → Git clone + pip install
│   ├── run_campaign(campaign, llm)    → Lance campagne d'attaque
│   ├── run_owasp_top10(llm)           → Campagne OWASP prédéfinie
│   ├── _parse_output(stdout)          → Parse résultats JSON
│   └── _generate_report(results)      → Rapport structuré
└── BUILTIN_CAMPAIGNS                  → Campagnes prédéfinies
```

#### Points d'attention ⚠️

- **Installation auto** : git clone + pip install -r requirements.txt
- **Coût API LLM** : 29 modules d'attaque → budget API non négligeable
- **Sandbox** : ne pas attaquer des LLMs en production sans autorisation
- **OWASP LLM Top 10** : mapping automatique des findings vers OWASP

#### Tests

| # | Test | Description |
|---|-------|-------------|
| T1 | `test_basilisk_import` | Import Basilisk |
| T2 | `test_basilisk_campaign_model` | Validation modèle |
| T3 | `test_basilisk_parse_output` | Parse sortie |
| T4 | `test_basilisk_owasp_campaign` | Campagne OWASP chargée |
| T5 | `test_basilisk_install_check` | Vérification installation |

---

## 6. ESTIMATION GLOBALE & RESSOURCES

### 6.1 Tableau récapitulatif

| RFC | Priorité | Effort (j) | Fichiers créés | Fichiers modifiés | Tests | Dépendances ext. |
|-----|:--------:|:----------:|:--------------:|:-----------------:|:-----:|:----------------:|
| RFC-001 masscan | **P1** | **1-2j** | 2-3 | 3-4 | 10 | `masscan` binaire |
| RFC-007 Semgrep | **P1** | **1.5-2j** | 4-5 | 3-4 | 8 | `semgrep` pip |
| RFC-006 EscalateGPT | **P1** | **1.5-2j** | 2-3 | 3-4 | 5 | LLM (optionnel) |
| RFC-002 nxc/netexec | **P2** | **3-4j** | 4-5 | 3-4 | 10 | `netexec` pipx |
| RFC-004 RAPTOR | **P2** | **2-3j** | 6-8 | 3-4 | 5 | Git + API LLM |
| RFC-003 bettercap | **P3** | **4-5j** | 5-6 | 4-5 | 10 | `bettercap` binaire |
| RFC-005 Basilisk | **P2** | **1.5-2j** | 5-7 | 2-3 | 5 | Git clone |
| **TOTAL** | — | **15-20j** | **28-37** | **21-28** | **53** | — |

### 6.2 Estimation par phase

| Phase | RFCs | Jours (1 dev) | Jours (2 devs) |
|-------|------|:------------:|:--------------:|
| **Phase 1** | RFC-001 + RFC-007 | 3 | 1.5-2 |
| **Phase 2a** | RFC-002 | 4 | 2 |
| **Phase 2b** | RFC-006 + RFC-004 | 4 | 2 |
| **Phase 3a** | RFC-003 | 5 | 3 |
| **Phase 3b** | RFC-005 | 2 | 1 |
| **Buffer** | Intégration, doc, bugs | 2 | 1.5 |
| **TOTAL** | — | **20j (1 mois)** | **10-12j (2.5 semaines)** |

### 6.3 Chemin critique

Le chemin critique est : **RFC-003 (bettercap)** — c'est le plus long et le plus complexe.
Il peut être parallélisé avec RFC-005 (Basilisk) en phase 3.

---

## 7. INTÉGRATION & LIVRABLES

### 7.1 Modifications communes à tous les RFCs

Chaque RFC nécessite de modifier/enrichir :

```
pyproject.toml          → Ajouter dépendances optionnelles (scanner, ad)
navmax/core/config.py   → Ajouter sections de config (masscan_rate, etc.)
README.md               → Mentionner les nouvelles capacités
CHANGELOG.md            → Journal des changements v0.7.0
```

### 7.2 Nouveaux modules API à créer

```
navmax/api/routes/wireless.py     → RFC-003 (bettercap)
navmax/api/routes/cloud.py        → RFC-006 (EscalateGPT) — si pas encore
```

### 7.3 Librairies Python à ajouter

```toml
# pyproject.toml — nouvelles dépendances
[project.optional-dependencies]
scanner = [
    "semgrep>=1.70.0",           # RFC-007
]
ad = [
    # impacket déjà présent
]
cloud = [
    # escalategpt peut être optionnel — fonctionne sans
]
wireless = [
    "aiohttp>=3.9.0",            # RFC-003 — déjà présent dans base
]
redteam = [
    # basilisk requirements installés via git clone
]
```

### 7.4 Binaires système requis

| Binaire | RFC | Install Linux | Install Windows (choco) |
|---------|:---:|---------------|-------------------------|
| `masscan` | 001 | `sudo apt install masscan` | `choco install masscan` |
| `netexec`/`nxc` | 002 | `pipx install netexec` | `pipx install netexec` |
| `bettercap` | 003 | `sudo snap install bettercap` | `choco install bettercap` |
| `semgrep` | 007 | `pip install semgrep` | `pip install semgrep` |

---

## 8. RECOMMANDATIONS & RISKS

### 8.1 Quick wins (faire en premier)

1. **masscan** (RFC-001) — le plus rapide, le plus gros impact utilitaire
2. **Semgrep** (RFC-007) — effort faible, comble un vide SAST critique
3. **EscalateGPT** (RFC-006) — enrichit le cloud module existant avec peu d'effort

### 8.2 Risques majeurs

| Risque | RFC | Impact | Mitigation |
|--------|:---:|:------:|------------|
| bettercap besoin root | 003 | Bloquant sans root | Détection précoce, fallback sur mode non-WiFi (ARP spoof simple) |
| nxc parsing fragile | 002 | Moyen (maintenance) | Tests de régression + abstraction parser |
| RAPTOR coût LLM | 004 | Élevé si usage intensif | Budget tracking, cache, mode « dry-run » |
| masscan sans perms | 001 | Bloquant sans CAP_NET_RAW | Message clair, fallback sur nmap/scanner TCP |
| Basilisk installation | 005 | Faible | Script d'install automatique |

### 8.3 Ordre d'exécution recommandé (1 dev)

```
Semaine 1 (P1 — Foundations)
├── Jour 1-2   → RFC-001 masscan       (2j)
├── Jour 2-3   → RFC-007 Semgrep       (2j, parallèle possible)
├── Jour 3-5   → RFC-006 EscalateGPT   (2j)

Semaine 2 (P2 — Exploitation)
├── Jour 5-8   → RFC-002 nxc/netexec   (4j)
├── Jour 8-10  → RFC-004 RAPTOR        (3j)

Semaine 3 (P3 — Advanced)
├── Jour 10-12 → RFC-005 Basilisk      (2j)
├── Jour 12-15 → RFC-003 bettercap     (4j)
└── Jour 15-17 → Intégration + Docs    (2j)
```

### 8.4 Ordre d'exécution parallélisé (2 devs)

```
Dev A                              Dev B
├── Semaine 1                     ├── Semaine 1
│   ├── RFC-001 masscan (2j)      │   ├── RFC-007 Semgrep (2j)
│   ├── RFC-006 EscalGPT (2j)     │   ├── RFC-002 nxc (4j)
│   └── RFC-004 RAPTOR (3j)       │   │
├── Semaine 2                     ├── Semaine 2
│   ├── RFC-005 Basilisk (2j)     │   └── (finir nxc)
│   └── RFC-003 bettercap (4j)    ├── Semaine 3
│                                 │   ├── Intégration + Tests (2j)
└── Semaine 3                     │   └── Docs + Bugfix (1j)
    └── Intégration + Tests (2j)  └──
```

---

## 9. CHECKLIST DE LIVRAISON PAR RFC

### Pour chaque RFC, vérifier :

- [ ] **Base** : Modèles de données (dataclass/Pydantic) avec validation
- [ ] **Connector** : Wrapper subprocess/API avec détection binaire
- [ ] **Analyzer** : Parsing des outputs structurés
- [ ] **CLI** : Commande(s) Typer avec `--help` complet
- [ ] **API** : Endpoint(s) REST avec schemas request/response
- [ ] **Tests** : ≥ 5 tests unitaires + 1 test d'intégration
- [ ] **Documentation** : Fichier `docs/<rfc>.md` avec exemples
- [ ] **Config** : Section dans `config.py` si paramétrable
- [ ] **__init__.py** : Exports publics propres
- [ ] **Fallback** : Comportement sans binaire externe
- [ ] **Sécurité** : Validation des entrées, pas d'injection commande

---

## 10. DÉPENDANCES DÉTAILLÉES PAR FICHIER

### RFC-001 (masscan) — Dépendances fichier par fichier

```
navmax/scanner/masscan_scanner.py
├── import asyncio
├── import shutil
├── from pydantic import BaseModel
├── from navmax.core.logging import get_logger
└── from navmax.core.exceptions import BinaryNotFoundError
```

### RFC-002 (nxc) — Dépendances fichier par fichier

```
navmax/ad/netexec_wrapper.py
├── import asyncio
├── import shutil
├── import re
├── from enum import Enum
├── from dataclasses import dataclass, field
├── from navmax.core.logging import get_logger
└── from navmax.core.exceptions import BinaryNotFoundError

navmax/ad/netexec_parser.py
├── import re
├── from dataclasses import dataclass
└── from .netexec_wrapper import NetExecResult, NetExecTarget
```

### RFC-003 (bettercap) — Dépendances fichier par fichier

```
navmax/wireless/bettercap_wrapper.py
├── import asyncio
├── import shutil
├── import aiohttp
├── from enum import Enum
├── from dataclasses import dataclass, field
├── from datetime import datetime
├── from navmax.core.logging import get_logger
└── from navmax.core.exceptions import BinaryNotFoundError

navmax/wireless/bettercap_runner.py
├── import asyncio
├── import os
├── import tempfile
└── from .bettercap_wrapper import BettercapModule
```

### RFC-004 (RAPTOR) — Dépendances fichier par fichier

```
navmax/ai/raptor_bridge.py
├── from enum import Enum
├── from dataclasses import dataclass, field
├── from navmax.ai.engine import AIEngine, get_engine
├── from navmax.core.logging import get_logger
└── from navmax.core.config import config
```

### RFC-005 (Basilisk) — Dépendances fichier par fichier

```
navmax/ai/redteam/basilisk_wrapper.py
├── import asyncio
├── import json
├── import shutil
├── from pathlib import Path
├── from pydantic import BaseModel
├── from navmax.core.logging import get_logger
└── from navmax.core.config import config
```

### RFC-006 (EscalateGPT) — Dépendances fichier par fichier

```
navmax/cloud/escalate_gpt.py
├── from pydantic import BaseModel, Field
├── from navmax.ai.engine import AIEngine, get_engine
├── from navmax.core.logging import get_logger
└── from navmax.cloud.scanner import IAMRisk, CloudFinding
```

### RFC-007 (Semgrep) — Dépendances fichier par fichier

```
navmax/scanner/semgrep_wrapper.py
├── import asyncio
├── import json
├── import shutil
├── from pathlib import Path
├── from pydantic import BaseModel, Field
├── from navmax.core.logging import get_logger
└── from navmax.core.exceptions import BinaryNotFoundError
```

---

*Fin du plan d'implémentation.*
