# NavMAX

<div align="center">

**Plateforme de cybersécurité offensive autonome — Dashboard Web, Cloud Scanner (AWS S3/IAM), Intruder (Burp-style), Plugin System — pilotée par IA, pour agents IA**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1088%2F1088-brightgreen.svg)](tests/)
[![Version](https://img.shields.io/badge/version-0.7.0--rc-purple.svg)](https://github.com/7ShIkI3/NavMAX)

*Scanner réseau · **Nuclei (10k+ CVE)** · Proxy MITM · Framework d'exploitation (25 exploits) · OSINT & Graphe · Sandbox Docker · **🧠 ReAct Agent IA** · **💣 Exploit Generator** · **🎭 Évasion polymorphique** · **📄 Rapports IA** · **🔗 SIEM/SOAR** · **🛡️ AD/LDAP** · **🔥 Firewall** · **🏗️ Infrastructure SOC** · **⚙️ Celery Tasks** · **📊 CVSS 3.1 + SARIF** · **🕸️ Playwright Spider** · **🔐 JWT + RBAC** · **🎯 MITRE ATT&CK** · **🖥️ Dashboard v2** · **🧠 ConnecteurIA** · **🖥️ Installeur Windows** · **🔐 Cracking** · **📡 Wireless** · **💻 Pwntools***

</div>

---

## 🎯 Vision

NavMAX est une plateforme de cybersécurité offensive **100% pilotable par IA**. Elle combine reconnaissance, exploitation, OSINT, Active Directory, firewall et reporting en un seul outil. L'IA intégrée planifie, exécute et rapporte — l'humain donne juste l'objectif.

```
$ navmax mission "Trouve la base de données sensible sur 10.0.0.0/24"

[phase_1] scanner → Port scan + détection services
[phase_2] osint   → Collecte DNS/WHOIS/SSL
[phase_3] exploit → Redis unauth sur 10.0.0.10
[phase_4] report  → Rapport HTML généré
```

### 🆕 v0.4.1 — ReAct Agent & Nuclei

| Module | Avant (v0.4.0) | Maintenant (v0.4.1) |
|---|---|---|
| 🧠 **ReAct Agent** | Mission Planner (NL→JSON) | ✅ **Boucle agentique** Observe→Think→Act avec 6 tools (scan_ports, scan_vulnerabilities, osint_investigate, exploit_check, ad_enumerate, generate_report) |
| 🔍 **Nuclei Scanner** | 17 signatures CVE codées en dur | ✅ **10 000+ templates** communautaires, scanning massif parallélisé |
| 🌐 **mitmproxy** | Proxy custom basique | ✅ **Proxy MITM complet** avec interception TLS, capture de flux, replay, export HAR |
| ⚙️ **Celery Tasks** | ❌ Aucun | ✅ **Task queue Redis** pour scans async avec progression SSE temps réel |
| 📊 **CVSS 3.1 + SARIF** | ❌ Aucun | ✅ **Scoring programmatique** CVSS 3.1 + export SARIF 2.1.0 compatible GitHub Code Scanning |
| 🎯 **MITRE ATT&CK** | ❌ Aucun | ✅ **Mapping automatique** CVE → techniques MITRE ATT&CK |
| 🕸️ **Playwright Spider** | Crawler basique | ✅ **Crawler SPA/JavaScript** pour apps React/Vue/Angular |
| 🔐 **Auth JWT + RBAC** | ❌ Aucune | ✅ **Admin/Operator/Viewer** avec JWT + rate limiting |
| 🖥️ **Dashboard** | ❌ Aucun | ✅ **Web UI single-file**, Mission Control SSE, Attack Graph canvas |
| ☁️ **Cloud** | ❌ Aucun | ✅ **S3 scanner**, IAM analyzer, Cloud Recon DNS (sans SDK) |
| 🛠️ **Intruder** | ❌ Aucun | ✅ **Fuzzer sniper/cluster_bomb**, 8 payloads prédéfinis |
| 🏗️ **Plugins** | ❌ Aucun | ✅ **@register_plugin**, discover/load/execute, API REST |
| 🔒 **Sécurité** | ❌ Aucune | ✅ **Audit P0+P1** (6 fixes), SAST CI/CD (Bandit+Safety) |
| 🐳 **Docker** | Basique | ✅ **PostgreSQL**, Nginx, volumes persistants, tout-en-un |
| 🔒 **Hermes** | Config faiblesses | ✅ auto_prune, tirith_fail_open→false, skills dupliquées mergées, mémoire consolidée |

### 🆕 v0.7.0-rc — Cracking, Wireless, Web, AD Wrappers

| Module | Description |
|---|---|
| 🔐 **Cracking** | hashcat (NTLM/WPA2/bcrypt), john (SSH/ZIP/KRB5), hydra (SSH/FTP/SMB/RDP) + bibliothèque (8 règles, 5 wordlists, 45 masques) |
| 📡 **Wireless** | WiFi (aircrack-ng, hcxtools, monitor mode, handshake, PMKID, hashcat -m 22000), BLE (bleak scanner/connect/GATT) |
| 🌐 **Web** | sqlmap (scan/crawl/dump), ffuf (dir busting, vhost discovery, parsing JSON) |
| 🛡️ **AD** | certipy (ESC1-13 exploitation), responder (NTLM capture, hashcat/john conversion) |
| 💻 **Pwntools** | shellcode gen, ROP gadgets, format string, pattern create/offset, asm/disasm, SSH remote |
| 🧪 **Tests** | 1088 (+261 vs v0.5.0) |
| 🐛 **Fixes** | impacket LOG, bcrypt 4.0.1, __main__.py, dashboard startup |

### 🆕 v0.5.0 — Installeur, Dashboard v2, Optimisations & Audit

| Module | Avant (v0.4.2) | Maintenant (v0.5.0) |
|---|---|---|
| 🖥️ **Installeur Windows** | ❌ Aucun | ✅ `install.ps1` (venv, raccourci bureau, menu Démarrer), `uninstall.ps1` (-KeepData), `launch.bat` one-click |
| 🧠 **Dashboard v2** | UI basique | ✅ **Sidebar navigation**, **ConnecteurIA** (providers, modèles, hardware), sélection modèle IA, tabs (Mission/Scans/Vuln/Graph/Système) |
| ⚡ **Perf** | Pas d'optimisations | ✅ Pool HTTP centralisé (-200ms/req), 16 indexes DB, probes parallélisées, lazy imports (-90ms) |
| 📐 **Qualité** | 4374 violations ruff | ✅ **-58%** violations, 22→2 silent swallowers, mypy core: 4→0 erreurs, 134 fichiers formatés |
| 🔧 **Fuzzer** | Faux négatifs | ✅ Détection regex (uid=, root:, Volume Serial), Content-Length diff, +16 payloads |
| 🔍 **Nuclei** | Préfixe cassé | ✅ `/api/v1/nuclei`, update-templates, startup check graceful |
| 📦 **Modules** | Censys dans shodan.py | ✅ CensysCollector dédié, intégrations refactorisées (thehive/misp/hub), cloud scanner pattern |
| 🧪 **Tests** | 773 | ✅ **827** (+54) |
| 🤖 **Agentic** | ❌ Aucun | ✅ **5 templates agents** (codeur/analyste/structure/plan/innovation), quality standards, orchestrateur YAML |
| 🔒 **Hermes** | Config faiblesses | ✅ auto_prune, tirith_fail_open→false, skills dupliquées mergées, mémoire consolidée |

### 🆕 v0.4.2 — Refactoring Mathis & Core Infra

| Module | Avant (v0.4.1) | Maintenant (v0.4.2) |
|---|---|---|
| 🔧 **Refactoring** | ❌ Aucun | ✅ Merge tou0/NavMAX — 81 fichiers, +2311/-896 lignes |
| 🏗️ **Core infra** | ❌ Aucun | ✅ constants.py (30+), exceptions.py (16), retry.py (@async_retry) |
| 🔒 **Sécurité** | Basique | ✅ Anti-XSS, anti-prompt-injection (8 patterns), Docker non-root, JWT 32+ chars |
| ⚡ **Robustesse** | Faible | ✅ Circuit breakers, graceful shutdown, timeouts LLM 180s, done_callback async |

### 🆕 v0.4.0 — Omni-Tool Infrastructure

| Module | Avant (v0.3.0) | Maintenant (v0.4.0) |
|---|---|---|
| 🛡️ **AD/LDAP** | ❌ Aucun | ✅ **10 modules** — LDAP connector, enumerator, trust graph, attack paths, vuln scanner (Kerberoasting, AS-REP, Delegation, Privileged), password spray, SMB scanner, ADCS scanner (ESC1-9), BloodHound export |
| 🔥 **Firewall** | ❌ Aucun | ✅ **6 modules** — FortiGate REST API (7 CVEs), StormShield SNS API (5 CVEs), rule analyzer (6 checks), AD×FW correlation |
| 🏗️ **Infrastructure** | ❌ Aucun | ✅ **SOC continu** — impact reporter, remediation advisor (PowerShell), continuous monitor (baseline + drift detection) |
| 📡 **API** | 16 endpoints | ✅ **28 endpoints** — +12 routes AD & Firewall |
| 🧪 **Tests** | 253 | ✅ **403** |

### 🧠 v0.3.0 — L'IA prend le contrôle

| Module | Avant (v0.2.0) | Maintenant (v0.3.0) |
|---|---|---|
| 🧠 **IA** | ❌ Aucune | ✅ **6 providers** (Ollama, llama.cpp, LM Studio, OpenAI, Anthropic, DeepSeek), **3 tiers** (Light ≤3B / Medium 7-8B / Heavy 70B+), auto-détection hardware, **4 modèles abliterated** |
| 📋 **Planification** | ❌ Aucune | ✅ **Mission Planner** — NL → JSON phases avec dépendances |
| 🔍 **Scanner** | TCP basique | ✅ **Contextuel** — service détecté → probes cascading (HTTP→dir busting, SMB→enum shares...) |
| 🛡️ **Vulns** | ❌ Aucune | ✅ **VulnDatabase** — 17 signatures CVE, matching version |
| 📡 **OSINT** | Collecte manuelle | ✅ **Monitor** — abonnement + alertes changements, **Semantic Search** — NL → graphe NetworkX |
| 💣 **Exploit** | 24 modules fixes | ✅ **AI Generator** — IA génère exploits sur mesure, sandbox test, **self-heal** |
| 🔄 **Pivot** | Manuel | ✅ **Auto-Pivot** — scan réseau interne, priorisation cibles |
| 🎭 **Évasion** | 4 encodeurs | ✅ **7 techniques polymorphiques** (rename vars, dead code, split strings, base64 wrap, int obfuscation...) |
| 🚀 **Mission** | ❌ Aucune | ✅ **One-Click** — `navmax mission "objectif"` → plan → execute → report |
| 📄 **Rapport** | ❌ Aucun | ✅ **AI Report Generator** — HTML + Markdown avec findings, sévérité, CVE, remediation |
| 🔗 **SIEM** | ❌ Aucun | ✅ **TheHive** + **MISP** + **IntegrationHub** |
| 📊 **Audit** | ❌ Aucun | ✅ **AuditLogger** — traçabilité complète de chaque action |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           🧠 ReAct Agent                                  │
│   Boucle agentique : Observe → Think → Act (6 tools)                     │
│   scan_ports · scan_vulnerabilities · osint_investigate                  │
│   exploit_check · ad_enumerate · generate_report                         │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────────┐
│                        ⚙️ CELERY TASK QUEUE                              │
│              Redis · Async Workers · SSE Real-time Progression            │
└────┬──────────┬──────────┬──────────┬──────────┬───────────┬────────────┘
     │          │          │          │          │           │
┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────────┐
│SCANNER │ │  PROXY │ │EXPLOIT │ │ OSINT  │ │REPORT  │ │   AUTH     │
│Nuclei  │ │mitm    │ │AI Gen  │ │Monitor │ │CVSS 3.1│ │JWT + RBAC  │
│10k CVE │ │Playwr. │ │Pivot   │ │Semantic│ │SARIF   │ │Admin/Op/   │
│Context.│ │Spider  │ │Évasion │ │Graph   │ │MITRE   │ │ Viewer     │
│Nmap    │ │        │ │        │ │        │ │ATT&CK  │ │            │
└────┬───┘ └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └────────────┘
     │         │          │          │          │
┌────▼─────────▼──────────▼──────────▼──────────▼─────────────────────────┐
│              SQLite / PostgreSQL + AUDIT TRAIL + REDIS                    │
│   Targets · Scans · Vulns · Graph · Workspaces · AuditLog · Tasks       │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                     ☁️ CLOUD SCANNER (NOUVEAU v0.4.1)                     │
│  S3 Scanner · IAM Analyzer · Cloud Recon DNS (sans SDK)                  │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                     🛡️ AD / LDAP ATTACK SURFACE                          │
│  Enumerator · Trust Graph · Attack Paths · Vuln Scanner                  │
│  Password Spray · SMB Scanner · ADCS ESC1-9 · BloodHound                 │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────────┐
│                        🔥 FIREWALL ATTACK SURFACE                         │
│  FortiGate (7 CVEs) · StormShield (5 CVEs) · Rule Analyzer               │
│  AD×FW Correlation · Base Provider Interface                             │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────────┐
│                        🏗️ INFRASTRUCTURE SOC                              │
│  Impact Reporter · Remediation Advisor (PS) · Continuous                  │
│  Monitor (baseline + drift detection + alerts)                            │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                        🖥️ DASHBOARD WEB UI (NOUVEAU v0.4.1)              │
│  Mission Control SSE · Attack Graph Canvas · Single-file Web UI          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Windows (recommandé)

```powershell
git clone https://github.com/7ShIkI3/NavMAX.git
cd NavMAX
.\scripts\install.ps1               # Installation standard (venv, raccourci bureau)
.\scripts\install.ps1 -DevMode      # Mode développement
```

Après installation : double-clic sur **"NavMAX Mission Control"** sur le Bureau, ou :

```cmd
%LOCALAPPDATA%\NavMAX\launch.bat
```

### Désinstallation

```powershell
.\scripts\uninstall.ps1                 # Suppression complète
.\scripts\uninstall.ps1 -KeepData       # Garder les données (DB, logs)
.\scripts\uninstall.ps1 -KeepData -KeepConfig  # Garder données + config
```

### Depuis les sources

```bash
git clone https://github.com/7ShIkI3/NavMAX.git
cd NavMAX
uv pip install -e .
```

**Prérequis :** Python 3.11+, Redis (pour Celery)

### Dépendances principales

```
ldap3 · impacket · mitmproxy · python-nmap · shodan · censys
redis · celery · cvss · neo4j · playwright · python-jose · passlib · slowapi
```

### IA locale (optionnel)

```bash
# Ollama (le plus simple)
winget install Ollama.Ollama
ollama pull huihui_ai/llama3.1-abliterated:8b   # 🔓 uncensored
ollama pull llama3.2:3b                            # Light

# Ou DeepSeek cloud (pas cher, ~$0.14/M tokens)
set DEEPSEEK_API_KEY=sk-...
```

### Celery (pour scans async)

```bash
# Démarrer le worker Celery
celery -A navmax.tasks worker --loglevel=info

# Démarrer le beat scheduler (optionnel)
celery -A navmax.tasks beat --loglevel=info
```

---

## 🚀 Utilisation

### 🚀 Mission One-Click

```bash
navmax mission "Audite la sécurité du réseau 10.0.0.0/24 et trouve un chemin vers la BDD"
```

### 🧠 ReAct Agent (NOUVEAU v0.4.1)

```bash
# Agent autonome : Observe → Think → Act
navmax react "Trouve les vulnérabilités critiques sur 10.0.0.0/24"

# Avec un objectif précis
navmax react "Énumère le domaine Active Directory et trouve un chemin vers Domain Admin"

# Scan + exploitation + rapport en une commande
navmax react "Scan 192.168.1.0/24, exploite les failles trouvées et génère un rapport SARIF"
```

### 🔍 Nuclei Scanner (NOUVEAU v0.4.1)

```bash
# Scan avec tous les templates (10 000+ CVEs)
navmax nuclei scan https://target.com --severity critical,high

# Scan avec templates spécifiques
navmax nuclei scan https://target.com -t cves,exposures -o results.json

# Scan réseau complet
navmax nuclei scan 10.0.0.0/24 --severity critical --concurrency 50
```

### 🧠 IA

```bash
# Status des providers et modèles dispo
navmax ai status

# Génération avec sélection auto du meilleur modèle
navmax ai generate "Analyse ce scan TCP" --tier medium

# Lister les modèles (dont abliterated 🔓)
navmax ai models
```

### 🔍 Scanner contextuel

```bash
navmax scan 192.168.1.1 -p 1-1000 --contextual  # probes auto
navmax scan 10.0.0.0/24 -p 22,80,443,3306,6379,8080
```

### 🛡️ Active Directory

```bash
# Énumération complète du domaine
navmax ad enumerate --domain corp.local --dc 192.168.1.10 -u admin -p 'Passw0rd!'

# Graphe de confiance + chemins d'attaque vers Domain Admin
navmax ad trust-graph --domain corp.local

# Scan de vulnérabilités AD (Kerberoasting, AS-REP, Delegation, Privileged)
navmax ad vuln-scan --domain corp.local

# Scan ADCS (ESC1 à ESC9)
navmax ad adcs-scan --domain corp.local

# Password spray
navmax ad spray --domain corp.local --mode smart

# Scan SMB
navmax ad smb-scan --domain corp.local

# Export BloodHound JSON
navmax ad export-bloodhound --domain corp.local -o bloodhound.json
```

### 🔥 Firewall

```bash
# Analyse FortiGate (vulnérabilités CVE)
navmax firewall fortigate --host 192.168.1.1 --token api-key

# Analyse StormShield
navmax firewall stormshield --host 192.168.1.254 --token api-key

# Analyse des règles
navmax firewall analyze --config firewall.json

# Corrélation AD × Firewall (règles exposant des DCs, etc.)
navmax firewall correlate --ad-report ad_report.json --fw-config firewall.json
```

### 🏗️ Infrastructure SOC

```bash
# Rapport d'impact métier
navmax infra impact --vuln-report vulns.json --critical-assets assets.json

# Plan de remédiation (PowerShell)
navmax infra remediate --vuln-report vulns.json

# Monitoring continu (baseline → drift detection)
navmax infra monitor --domain corp.local --baseline baseline.json
```

### 🕸️ OSINT + Surveillance

```bash
navmax osint example.com --depth 2
navmax osint monitor example.com --interval 24h   # alerte changements
navmax osint graph search "sous-domaines avec login liés à IP russe"
```

### 💣 Exploitation

```bash
navmax exploits --search redis
navmax check redis_unauth -r 192.168.1.10
navmax exploit generate --service apache --version 2.4.49  # IA génère l'exploit
navmax payload -t reverse_shell -f python -h 10.0.0.1 -p 4444
navmax payload mutate exploit.py --iterations 5   # polymorphisme
```

### 🌐 Proxy MITM (mitmproxy — NOUVEAU v0.4.1)

```bash
# Proxy MITM avec interception TLS
navmax proxy --port 8080 --intercept --tls

# Capture et replay de flux
navmax proxy --port 8080 --capture --export-har session.har

# Replay d'une session enregistrée
navmax proxy replay session.har --rate 1.0

# Playwright Spider — Crawler SPA (React/Vue/Angular)
navmax proxy spider https://app.target.com --depth 3 --headless
```

### 🖥️ Dashboard (NOUVEAU v0.4.1)

```bash
# Lancer le dashboard web
navmax dashboard  # → http://localhost:8000/dashboard
```

### ☁️ Cloud Scanner (NOUVEAU v0.4.1)

```bash
# Scan S3 bucket
navmax cloud scan-s3 my-bucket --region us-east-1

# Reconnaissance DNS cloud
navmax cloud recon example.com
```

### 🛠️ Intruder (NOUVEAU v0.4.1)

```bash
# Attaque fuzzer avec payloads prédéfinis
navmax intruder attack --request req.txt --positions "body:user" --payloads xss
```

### 🏗️ Plugins (NOUVEAU v0.4.1)

```bash
# Lister les plugins disponibles
navmax plugins list

# Exécuter un plugin communautaire
navmax plugins run community/nuclei-automation
```

### 📄 Rapports

```bash
# Rapport IA structuré (HTML/Markdown)
navmax report mission-123 --format html
navmax report mission-123 --format md

# Export SARIF 2.1.0 (compatible GitHub Code Scanning)
navmax report mission-123 --format sarif --output scan.sarif

# Scoring CVSS 3.1
navmax report mission-123 --format cvss
```

### 🔗 Intégrations SIEM/SOAR

```python
from navmax.integrations import TheHiveConnector, IntegrationHub, AlertData

hub = IntegrationHub()
hub.add_connector("thehive", TheHiveConnector("https://hive.example.com", "api-key"))
await hub.send_alert(AlertData(title="Redis unauth", severity=3))
```

---

## 🧠 IA — Fonctionnement

### Tiers de modèles

| Tier | Taille | Tâches | Modèles (dont 🔓 abliterated) |
|---|---|---|---|
| **Light** | 1-3B | Classification, extraction, parsing | `llama3.2:3b`, `qwen2.5:3b`, `phi3:3.8b` |
| **Medium** | 7-8B | Planification, analyse, résumé | 🔓 `huihui_ai/llama3.1-abliterated:8b`, `llama3.1:8b`, `mistral:7b` |
| **Heavy** | 70B+ | Génération de code, raisonnement | 🔓 `huihui_ai/llama3.1-abliterated:70b`, `deepseek-v4-pro` |

### Providers supportés

| Provider | Type | Setup |
|---|---|---|
| **Ollama** | Local HTTP | `winget install Ollama.Ollama` |
| **llama.cpp** | Local GGUF | GPU NVIDIA (CUDA) |
| **LM Studio** | Local GUI | Interface Windows |
| **DeepSeek** | Cloud | `$DEEPSEEK_API_KEY` |
| **OpenAI** | Cloud | `$OPENAI_API_KEY` |
| **Anthropic** | Cloud | `$ANTHROPIC_API_KEY` |

### Sélection automatique

```
SI RAM < 8GB  → Light (3B) local, Medium/Heavy → cloud
SI RAM ≥ 16GB → Light + Medium (7-8B) local, Heavy → cloud
SI GPU ≥ 16GB → Tout en local possible (70B Q4)

SI cybersécurité → priorité modèles abliterated 🔓
SI airgap mode → cloud désactivé, 100% local
```

---

## 🔌 API REST

### IA & Core

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/ai/status` | État IA (providers, hardware, modèles) |
| `POST` | `/api/v1/ai/generate` | Génération avec sélection auto |
| `POST` | `/api/v1/ai/stream` | Streaming SSE |
| `GET` | `/api/v1/ai/models` | Modèles disponibles (dont 🔓) |
| `POST` | `/api/v1/targets/` | Créer une cible |
| `POST` | `/api/v1/scans/` | Lancer un scan |
| `POST` | `/api/v1/proxy/start` | Démarrer proxy MITM |
| `POST` | `/api/v1/proxy/scan` | Scanner web |
| `POST` | `/api/v1/proxy/fuzz` | Fuzzer |
| `GET` | `/api/v1/exploit/search` | Rechercher exploits |
| `POST` | `/api/v1/exploit/run` | Exécuter exploit |
| `POST` | `/api/v1/exploit/generate` | IA génère un exploit |
| `POST` | `/api/v1/osint/investigate` | Investigation complète |
| `POST` | `/api/v1/osint/monitor` | Abonnement surveillance |
| `POST` | `/api/v1/workspaces/` | Créer workspace |
| `POST` | `/api/v1/missions/execute` | Mission One-Click |

### 🆕 v0.4.1 — ReAct & Nuclei & Auth

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scan/nuclei` | Scan Nuclei (10k+ templates CVE) |
| `GET` | `/api/v1/scans/{id}/status` | Statut scan async (Celery) |
| `GET` | `/api/v1/scans/{id}/stream` | Progression temps réel (SSE) |
| `POST` | `/api/v1/auth/login` | Authentification JWT |
| `POST` | `/api/v1/auth/register` | Création compte |
| `GET` | `/api/v1/auth/me` | Profil utilisateur courant |

### 🛡️ Active Directory

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/ad/enumerate` | Énumération domaine |
| `POST` | `/api/v1/ad/trust-graph` | Graphe de confiance |
| `GET` | `/api/v1/ad/attack-paths` | Chemins d'attaque vers DA |
| `POST` | `/api/v1/ad/vuln-scan` | Scan vulnérabilités AD |
| `POST` | `/api/v1/ad/spray` | Password spray |
| `POST` | `/api/v1/ad/smb-scan` | Scan SMB |
| `POST` | `/api/v1/ad/adcs-scan` | Scan ADCS (ESC1-9) |
| `POST` | `/api/v1/ad/export-bloodhound` | Export BloodHound JSON |

### 🔥 Firewall

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/firewall/fortigate` | Analyse FortiGate |
| `POST` | `/api/v1/firewall/stormshield` | Analyse StormShield |
| `POST` | `/api/v1/firewall/analyze` | Analyse des règles |
| `POST` | `/api/v1/firewall/correlate` | Corrélation AD × FW |

### 🆕 v0.4.1 — Dashboard & Cloud & Intruder & Plugins

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/dashboard` | Web UI Dashboard |
| `GET` | `/api/v1/dashboard/stream` | Mission Control SSE |
| `GET` | `/api/v1/dashboard/graph` | Attack Graph canvas |
| `POST` | `/api/v1/cloud/scan-s3` | Scan bucket S3 |
| `POST` | `/api/v1/cloud/analyze-iam` | Analyse IAM |
| `POST` | `/api/v1/cloud/recon` | Cloud Recon DNS |
| `POST` | `/api/v1/plugins/discover` | Découvrir plugins |
| `POST` | `/api/v1/plugins/load` | Charger plugin |
| `POST` | `/api/v1/plugins/execute` | Exécuter plugin |
| `GET` | `/api/v1/plugins/list` | Lister plugins |
| `POST` | `/api/v1/proxy/intruder` | Intruder / Fuzzer |
| `GET` | `/api/v1/proxy/intruder/payloads` | Payloads prédéfinis |

---

## 📊 Fonctionnalités détaillées

### 🆕 v0.4.1

#### 🧠 ReAct Agent
- **Boucle agentique** Observe→Think→Act avec raisonnement step-by-step
- **6 tools intégrés** : scan_ports, scan_vulnerabilities, osint_investigate, exploit_check, ad_enumerate, generate_report
- **Mémoire persistante** : conserve le contexte entre les tours
- **Planification dynamique** : ajuste le plan en fonction des résultats intermédiaires
- Remplace le Mission Planner (v0.3.0) avec une approche plus flexible

#### 🔍 Nuclei Scanner
- **10 000+ templates** CVE maintenus par la communauté ProjectDiscovery
- Scan parallélisé avec contrôle de concurrence
- Filtrage par sévérité (critical, high, medium, low, info)
- Export multi-format (JSON, SARIF, HTML, Markdown)
- Mise à jour automatique des templates (`nuclei -update`)

#### 🌐 mitmproxy
- **Interception TLS** : décryptage transparent du trafic HTTPS
- **Capture de flux** : enregistrement complet des requêtes/réponses
- **Replay** : rejeu de sessions à débit contrôlé
- **Export HAR** : compatible avec les outils d'analyse web standards
- **Scriptable** : modifications à la volée via scripts Python

#### ⚙️ Celery Tasks
- **Task queue Redis** pour l'exécution asynchrone des scans
- **Progression SSE** : statuts temps réel via Server-Sent Events
- **File d'attente prioritaire** : tâches critiques passent avant
- **Workers parallèles** : scaling horizontal
- **Persistance** : reprise après redémarrage

#### 📊 CVSS 3.1 + SARIF
- **CVSS 3.1** : scoring programmatique (Base / Temporal / Environmental)
- **SARIF 2.1.0** : export compatible GitHub Code Scanning et outils CI/CD
- **Mapping CVE→score** : enrichissement automatique des vulnérabilités
- **Intégration continue** : validation dans les pipelines GitHub Actions

#### 🎯 MITRE ATT&CK
- **Mapping automatique** CVE → techniques et tactiques MITRE ATT&CK
- **Tableau de bord** : visualisation des techniques exploitées par phase
- **Graphe de progression** : suivi de la couverture ATT&CK par mission
- **Recommandations** : identification des techniques manquantes

#### 🕸️ Playwright Spider
- **Crawler SPA** : support natif des applications React/Vue/Angular
- **Exécution JavaScript** : rendu complet des pages dynamiques
- **Détection de formulaires** : identification des points d'entrée
- **Capture d'écran** : preuve visuelle des pages crawlees
- **Mode headless/full browser** : selon les besoins

#### 🔐 Auth JWT + RBAC
- **JWT** : authentification sans état avec refresh tokens
- **RBAC** : 3 rôles (Admin, Operator, Viewer)
- **Rate limiting** : protection contre le bruteforce (SlowAPI)
- **Hachage** : mots de passe via passlib (bcrypt)
- **Routes protégées** : middleware de vérification automatique

### 🛡️ AD / LDAP (v0.4.0)
- **LDAP Connector** : connexion SSL/TLS, binding, pagination
- **Enumerator** : users, groups, computers, OUs, GPOs, trusts, ACLs
- **Trust Graph** : NetworkX multi-domaine, chemins d'attaque, DA effective
- **Attack Paths** : analyse des chemins critiques, risques, recommandations
- **Vuln Scanner** : Kerberoasting, AS-REP Roasting, Unconstrained Delegation, Privileged Users
- **Password Spray** : wordlist saisonnière, mode smart/auto, lockout protection
- **SMB Scanner** : shares, permissions, null sessions, enumeration DCs/servers
- **ADCS Scanner** : ESC1 à ESC9, templates vulnérables, CAs, findings détaillés
- **BloodHound Export** : format JSON compatible BloodHound CE

### 🔥 Firewall (v0.4.0)
- **FortiGate** : REST API admin, version detection, 7 CVEs (CVE-2022-40684 auth bypass, CVE-2023-27997 RCE, CVE-2023-33308 stack overflow, CVE-2024-21762 out-of-bounds write, CVE-2024-23113 format string, CVE-2024-23672 path traversal, CVE-2024-47575 info disclosure)
- **StormShield** : SNS API, version detection, 5 CVEs (CVE-2020-11711 XSS, CVE-2020-11712 file upload, CVE-2020-11713 CSRF, CVE-2023-22237 buffer overflow, CVE-2023-36558 authentication bypass)
- **Rule Analyzer** : 6 checks (any→any, high-risk ports, shadowed rules, disabled rules, overly permissive, unused rules)
- **AD×FW Correlation** : règles exposant des DCs, comptes à privilèges, chemins critiques

### 🏗️ Infrastructure SOC (v0.4.0)
- **Impact Reporter** : scoring métier (critique ≥8, haut ≥5, moyen ≥3, bas), P1-P4 priorités
- **Remediation Advisor** : plan d'actions avec commandes PowerShell, IDs MITRE ATT&CK, priorisation
- **Continuous Monitor** : capture baseline → check périodique → drift detection → alertes

### 🧠 IA Engine (v0.3.0)
- **6 providers** : Ollama, llama.cpp (GPU), LM Studio, OpenAI, Anthropic, DeepSeek
- **3 tiers** : Light (≤3B), Medium (7-8B), Heavy (70B+)
- **Auto-détection hardware** : RAM, GPU, CPU → sélection automatique du tier
- **4 modèles abliterated** 🔓 : uncensored pour cybersécurité offensive
- **ModelSelector** : scan × match catalogue × fallback → meilleur modèle dispo
- **Fallback automatique** : local → cloud, Heavy → Medium → Light
- **Mode airgap** : 100% offline (modèles locaux uniquement)

### 📋 Mission Planner (v0.3.0)
- Objectif NL → JSON phases avec dépendances topologiques
- Supporte les contraintes, services connus, vulnérabilités connues
- Fallback automatique si l'IA produit du JSON invalide

### 🔍 Scanner
- TCP Connect Scan asynchrone (200 connexions simultanées)
- **Contextuel** : HTTP → dir busting + tech fingerprint, Redis → INFO, SSH → version...
- **VulnDatabase** : 17 signatures CVE (Apache, OpenSSH, Redis, SMB EternalBlue, Log4Shell, Docker, Kubernetes...)
- Banner grabbing 30+ services
- Fingerprinting OS (TTL, TCP flags)

### 🕸️ OSINT
- DNS, WHOIS, SSL, Web, Shodan, Censys, crt.sh
- **OSINT Monitor** : abonnement domaine/IP, détection changements, alertes
- **Semantic Graph Search** : NL → requêtes graphe NetworkX
- Graphe : 17 types entités, 27 types relations, export Cytoscape/Sigma.js

### 💣 Exploitation
- **24 exploits** + **AI Generator** (IA génère exploits sur mesure)
- **Self-heal** : sandbox test → échec → IA corrige → retest (max 3 tentatives)
- **Auto-Pivot** : scan réseau interne, priorisation cibles haute valeur
- **7 techniques polymorphiques** : rename vars, dead code, split strings, base64 wrap...
- 4 encodeurs (Shikata-ga-nai, AES-CTR, substitution, multi-layer)
- Sandbox Docker, payloads, handler, post-exploitation

### 📄 Reporting & Intégration (v0.3.0)
- **AI Report Generator** : HTML + Markdown avec findings, sévérité, CVE
- **TheHive** + **MISP** connectors
- **IntegrationHub** : envoi simultané à tous les SIEM/SOAR

### 📊 Audit (v0.3.0)
- **AuditLogger** : chaque action horodatée, journalisée, liée à une mission
- Context manager `async with audit.track(...)`
- Status : started → completed / failed / rolled_back

---

## 🧪 Tests

```bash
pytest tests/ -v
# 827 passed, 45 skipped
```

| Métrique | Valeur |
|---|---|
| Tests unitaires | 827 |
| Couverture modules | 100% (16/16 modules) |
| CI/CD | GitHub Actions (lint + test) |
| Qualité | ruff -58% violations, mypy core 0 erreurs |

---

## 📁 Structure

```
NavMAX/
├── navmax/
│   ├── ai/                # 🧠 IA Engine (v0.3.0)
│   │   ├── engine.py      #   Orchestrateur multi-provider
│   │   ├── selector.py    #   ModelSelector × catalogue × fallback
│   │   ├── models_catalog.py  # 27 modèles (dont 4 abliterated)
│   │   ├── react_agent.py #   🔁 ReAct Agent (NOUVEAU v0.4.1)
│   │   ├── hardware.py    #   Détection RAM/GPU/CPU auto
│   │   └── providers/     #   Ollama, llama.cpp, LM Studio, OpenAI, Anthropic, DeepSeek
│   ├── ad/                # 🛡️ Active Directory (v0.4.0)
│   │   ├── connector.py   #   LDAP SSL/TLS + binding
│   │   ├── enumerator.py  #   Users, groups, computers, OUs, GPOs, trusts
│   │   ├── trust_graph.py #   NetworkX multi-domaine + chemins d'attaque
│   │   ├── attack_paths.py    # Analyse chemins critiques
│   │   ├── vuln_scanner.py    # Kerberoasting, AS-REP, Delegation, Privileged
│   │   ├── password_spray.py  # Smart spray + lockout protection
│   │   ├── smb_scanner.py     # Shares, permissions, null sessions
│   │   ├── adcs_scanner.py    # ESC1-9 + templates + CAs
│   │   └── bloodhound_export.py  # JSON BloodHound CE
│   ├── firewall/          # 🔥 Firewall (v0.4.0)
│   │   ├── base.py        #   Interface provider abstraite
│   │   ├── fortigate.py   #   REST API + 7 CVEs
│   │   ├── stormshield.py #   SNS API + 5 CVEs
│   │   ├── rule_analyzer.py   # 6 checks de règles
│   │   └── correlation.py     # AD × FW correlation
│   ├── infrastructure/    # 🏗️ SOC continu (v0.4.0)
│   │   ├── impact_reporter.py     # Scoring métier + priorités
│   │   ├── remediation_advisor.py # Plan PS + MITRE ATT&CK
│   │   └── continuous_monitor.py  # Baseline + drift + alertes
│   ├── scanner/
│   │   ├── contextual.py      #   Scan adaptatif
│   │   ├── nuclei_scanner.py  #   🔍 Nuclei 10k+ templates (NOUVEAU v0.4.1)
│   │   ├── nmap_scanner.py    #   🔍 Wrapper async nmap (NOUVEAU v0.4.1)
│   │   └── vuln_db.py         #   17 signatures CVE
│   ├── proxy/
│   │   ├── mitm.py            #   🌐 mitmproxy (NOUVEAU v0.4.1)
│   │   └── playwright_spider.py # 🕸️ Crawler SPA (NOUVEAU v0.4.1)
│   ├── exploit/
│   │   ├── ai_generator.py #  IA génère exploits
│   │   ├── auto_pivot.py  #   Lateral movement auto
│   │   ├── evasion.py     #   7 techniques polymorphiques
│   │   └── modules/       #   24 modules d'exploit
│   ├── cloud/             # ☁️ Cloud Scanner (NOUVEAU v0.4.1)
│   ├── osint/
│   │   ├── monitor.py     #   Abonnement + alertes
│   │   └── graph/semantic_search.py  # NL → graphe
│   ├── tasks/             # ⚙️ Celery (NOUVEAU v0.4.1)
│   ├── orchestrator/      # 🚀 One-Click mission
│   ├── reporting/
│   │   ├── cvss_scorer.py     # 📊 CVSS 3.1 (NOUVEAU v0.4.1)
│   │   ├── sarif_exporter.py  # 📊 SARIF 2.1.0 (NOUVEAU v0.4.1)
│   │   └── ai_report.py      # Rapports IA HTML/MD
│   ├── integrations/      # 🔗 TheHive, MISP, Hub
│   ├── core/
│   │   ├── constants.py      # 30+ constantes (v0.4.2)
│   │   ├── exceptions.py     # 16 exceptions typées (v0.4.2)
│   │   ├── retry.py          # @async_retry backoff (v0.4.2)
│   │   ├── http_client.py    # 🌐 Pool HTTP centralisé (NOUVEAU v0.5.0)
│   │   ├── lazy_import.py    # ⚡ Lazy importer (NOUVEAU v0.5.0)
│   │   └── utils.py          # safe_close_writer (v0.4.2)
│   ├── db/                # SQLAlchemy async models + 16 indexes (v0.5.0)
│   ├── api/               # FastAPI routes REST (42+ endpoints)
│   │   └── static/        #   🖥️ Dashboard v2 (v0.5.0)
│   └── sdk/               # Client Python async
├── scripts/               # 🖥️ Installeur Windows (NOUVEAU v0.5.0)
│   ├── install.ps1        #   Installation one-click
│   ├── uninstall.ps1      #   Désinstallation (-KeepData)
│   ├── launch.bat         #   Lancement + dashboard
│   └── navmax.ico         #   Icône application
├── tests/                 # 1088 tests (+261 vs v0.5.0)
├── .github/workflows/     # 🔒 SAST CI/CD (NOUVEAU)
├── nginx/                 # 🐳 Reverse proxy (NOUVEAU)
├── Dockerfile             # 🐳 Multi-stage (NOUVEAU)
├── .env.example           # 🐳 Configuration (NOUVEAU)
└── pyproject.toml
```

---

## 📄 License

MIT © Raphaël Pascaud

---

<div align="center">

**NavMAX** — *From tool for AI, to AI as the tool* 🤖

</div>
