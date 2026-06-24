# NavMAX

<div align="center">

**Plateforme de cybersécurité offensive autonome — pilotée par IA, pour agents IA**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-253%2F253-brightgreen.svg)](tests/)
[![Version](https://img.shields.io/badge/version-0.3.0-orange.svg)](https://github.com/7ShIkI3/NavMAX)

*Scanner réseau · Proxy MITM · Framework d'exploitation (24 exploits) · OSINT & Graphe · Sandbox Docker · **🧠 IA Autonome** · **💣 Exploit Generator** · **🎭 Évasion polymorphique** · **📄 Rapports IA** · **🔗 SIEM/SOAR***

</div>

---

## 🎯 Vision

NavMAX est une plateforme de cybersécurité offensive **100% pilotable par IA**. Elle combine reconnaissance, exploitation, OSINT et reporting en un seul outil. L'IA intégrée planifie, exécute et rapporte — l'humain donne juste l'objectif.

```
$ navmax mission "Trouve la base de données sensible sur 10.0.0.0/24"

[phase_1] scanner → Port scan + détection services
[phase_2] osint   → Collecte DNS/WHOIS/SSL
[phase_3] exploit → Redis unauth sur 10.0.0.10
[phase_4] report  → Rapport HTML généré
```

### 🆕 v0.3.0 — L'IA prend le contrôle

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
┌──────────────────────────────────────────────────────────────┐
│                     🧠 AI ENGINE                              │
│  6 providers · 3 tiers (Light/Medium/Heavy) · Auto-select    │
│  Ollama · llama.cpp · LM Studio · OpenAI · Anthropic · DeepSeek│
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                   🚀 MISSION ORCHESTRATOR                      │
│     One-Click: Plan → Execute → Pivot → Report                │
└────┬──────────┬──────────┬──────────┬───────────┬────────────┘
     │          │          │          │           │
┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────────┐
│ SCANNER │ │  PROXY │ │ EXPLOIT│ │  OSINT  │ │ REPORTING  │
│Context. │ │ MITM   │ │AI Gen  │ │Monitor  │ │HTML/MD     │
│Vuln DB  │ │Fuzzer  │ │Pivot   │ │Semantic │ │SIEM/SOAR   │
│17 CVE   │ │Crawler │ │Évasion │ │Graph    │ │TheHive/MISP│
└────┬────┘ └───┬────┘ └───┬────┘ └────┬────┘ └────────────┘
     │          │          │           │
┌────▼──────────▼──────────▼───────────▼──────────────────────┐
│              SQLite / PostgreSQL + AUDIT TRAIL               │
│   Targets · Scans · Vulns · Graph · Workspaces · AuditLog   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

```bash
git clone https://github.com/7ShIkI3/NavMAX.git
cd NavMAX
uv pip install -e .
```

**Prérequis :** Python 3.11+

### IA locale (optionnel)

```bash
# Ollama (le plus simple)
winget install Ollama.Ollama
ollama pull huihui_ai/llama3.1-abliterated:8b   # 🔓 uncensored
ollama pull llama3.2:3b                            # Light

# Ou DeepSeek cloud (pas cher, ~$0.14/M tokens)
set DEEPSEEK_API_KEY=sk-...
```

---

## 🚀 Utilisation

### 🚀 Mission One-Click

```bash
navmax mission "Audite la sécurité du réseau 10.0.0.0/24 et trouve un chemin vers la BDD"
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

### 🌐 Proxy MITM

```bash
navmax proxy -p 8080 --intercept
navmax webscan http://target.com/page?id=1
navmax fuzz http://target.com/search?q=test -c xss,sqli
```

### 📄 Rapports

```bash
navmax report mission-123 --format html  # rapport IA structuré
navmax report mission-123 --format md
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

---

## 📊 Fonctionnalités détaillées

### 🧠 IA Engine (NOUVEAU v0.3.0)
- **6 providers** : Ollama, llama.cpp (GPU), LM Studio, OpenAI, Anthropic, DeepSeek
- **3 tiers** : Light (≤3B), Medium (7-8B), Heavy (70B+)
- **Auto-détection hardware** : RAM, GPU, CPU → sélection automatique du tier
- **4 modèles abliterated** 🔓 : uncensored pour cybersécurité offensive
- **ModelSelector** : scan × match catalogue × fallback → meilleur modèle dispo
- **Fallback automatique** : local → cloud, Heavy → Medium → Light
- **Mode airgap** : 100% offline (modèles locaux uniquement)

### 📋 Mission Planner (NOUVEAU)
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

### 📄 Reporting & Intégration (NOUVEAU)
- **AI Report Generator** : HTML + Markdown avec findings, sévérité, CVE
- **TheHive** + **MISP** connectors
- **IntegrationHub** : envoi simultané à tous les SIEM/SOAR

### 📊 Audit (NOUVEAU)
- **AuditLogger** : chaque action horodatée, journalisée, liée à une mission
- Context manager `async with audit.track(...)`
- Status : started → completed / failed / rolled_back

---

## 🧪 Tests

```bash
pytest tests/ -v
# 253 passed
```

---

## 📁 Structure

```
NavMAX/
├── navmax/
│   ├── ai/                # 🧠 IA Engine (NOUVEAU)
│   │   ├── engine.py      #   Orchestrateur multi-provider
│   │   ├── selector.py    #   ModelSelector × catalogue × fallback
│   │   ├── models_catalog.py  # 27 modèles (dont 4 abliterated)
│   │   ├── mission_planner.py # NL → phases JSON
│   │   ├── hardware.py    #   Détection RAM/GPU/CPU auto
│   │   └── providers/     #   Ollama, llama.cpp, LM Studio, OpenAI, Anthropic, DeepSeek
│   ├── scanner/
│   │   ├── contextual.py  #   Scan adaptatif (NOUVEAU)
│   │   └── vuln_db.py     #   17 signatures CVE (NOUVEAU)
│   ├── proxy/             #   MITM, fuzzer, crawler, fuzzer structurel
│   ├── exploit/
│   │   ├── ai_generator.py #  IA génère exploits (NOUVEAU)
│   │   ├── auto_pivot.py  #   Lateral movement auto (NOUVEAU)
│   │   ├── evasion.py     #   7 techniques polymorphiques (NOUVEAU)
│   │   └── modules/       #   24 modules d'exploit
│   ├── osint/
│   │   ├── monitor.py     #   Abonnement + alertes (NOUVEAU)
│   │   └── graph/semantic_search.py  # NL → graphe (NOUVEAU)
│   ├── orchestrator/      # 🚀 One-Click mission (NOUVEAU)
│   ├── reporting/         # 📄 Rapports IA HTML/MD (NOUVEAU)
│   ├── integrations/      # 🔗 TheHive, MISP, Hub (NOUVEAU)
│   ├── core/              # Config, logging, plugins, audit
│   ├── db/                # SQLAlchemy async models
│   ├── api/               # FastAPI routes REST
│   └── sdk/               # Client Python async
├── tests/                 # 253 tests
├── .github/workflows/     # CI/CD
└── pyproject.toml
```

---

## 📄 License

MIT © Raphaël Pascaud

---

<div align="center">

**NavMAX** — *From tool for AI, to AI as the tool* 🤖

</div>
