# NavMAX — Plan d'Architecture & Développement

## Vision
Plateforme de cybersécurité unifiée **pilotable par des agents IA**, combinant :
- 🔍 **Nmap** → Reconnaissance réseau
- 🌐 **Burp Suite** → Analyse & interception web
- 💣 **Metasploit** → Exploitation & post-exploitation (24 exploits)
- 🕸️ **Maltego** → OSINT & graphe de relations

---

## Statut : v0.2.0 ✅

| Phase | Contenu | Statut |
|-------|---------|--------|
| 1 | Fondations (Core, Scanner, DB, API, SDK) | ✅ v0.1.0 |
| 2 | Proxy (MITM, Interception, Repeater, Scanner Web, Fuzzer) | ✅ v0.1.0 |
| 3 | Exploit (Modules, Payloads, Handler, Post-exploit) | ✅ v0.1.0 |
| 4 | OSINT & Graphe (DNS, WHOIS, SSL, Web, NetworkX, Transforms) | ✅ v0.1.0 |
| 5 | **Sandbox Docker** | ✅ v0.2.0 |
| 6 | **Workspaces (projets)** | ✅ v0.2.0 |
| 7 | **24 exploits modulaires** | ✅ v0.2.0 |
| 8 | **Encodeurs polymorphiques** (Shikata-ga-nai, AES-CTR...) | ✅ v0.2.0 |
| 9 | **Crawler web + Fuzzer structurel** | ✅ v0.2.0 |
| 10 | **OSINT Shodan/Censys/crt.sh** | ✅ v0.2.0 |
| 11 | **CI/CD GitHub Actions** | ✅ v0.2.0 |
| 12 | **Documentation MkDocs** | ✅ v0.2.0 |

---

## Prochaines étapes (v0.3.0)

### P3 — IA & Automatisation
- **Moteur de recommandation IA** (Ollama/Llama) : analyse les scans et propose les prochaines actions
- **Interface conversationnelle** (CLI + API WebSocket) : piloter NavMAX en langage naturel
- **Auto-apprentissage** : ajustement des paramètres selon l'environnement

### P2 — Proxy avancé
- **Moteur de règles** : auto-modification des requêtes (remplacer JWT, injecter headers)
- **Crawling JavaScript** (Playwright/Selenium) : scraper les SPAs

### P2 — OSINT avancé
- **Monitoring continu** : relancer les collectes et alerter sur les changements
- **Export Neo4j** : graphe persistant avec requêtes Cypher

### P4 — Qualité
- **Tests d'intégration** sur réseau de test
- **Documentation complète** (guides, tutoriels, workflows)

---

## Architecture Générale

```
┌─────────────────────────────────────────────────┐
│                  AGENT SDK                       │
│  Python · CLI · API REST · WebSocket            │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              API GATEWAY (FastAPI)               │
│  Auth · Rate Limit · Logging · Validation        │
└────┬──────────┬──────────┬──────────┬───────────┘
     │          │          │          │
┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────────┐
│ SCANNER │ │  PROXY │ │ EXPLOIT│ │   OSINT    │
│ (Nmap)  │ │ (Burp) │ │ (MSF)  │ │ (Maltego)  │
│         │ │+Crawler│ │+24 exp │ │+Shodan    │
│         │ │+StrFuzz│ │+Sandbox│ │+Censys    │
└────┬────┘ └───┬────┘ └───┬────┘ └─────┬──────┘
     │          │          │            │
┌────▼──────────▼──────────▼────────────▼──────┐
│              CORE DATABASE                     │
│  Workspaces · Targets · Vulns · Scans         │
│  SQLite (dev) → PostgreSQL (prod)              │
└────────────────────────────────────────────────┘
```

---

## Stack Technique

| Couche | Technologie |
|--------|-------------|
| Langage | **Python 3.11+** |
| API | **FastAPI** + Uvicorn |
| Async | **asyncio** natif |
| DB | **SQLite** (dev) → **PostgreSQL** (prod) |
| ORM | **SQLAlchemy 2.0** (async) |
| Proxy | **mitmproxy** library |
| Scan | **scapy** + sockets natifs |
| OSINT | **httpx** (async HTTP) |
| Graphe | **NetworkX** (mémoire) → **Neo4j** (persistant) |
| Sandbox | **Docker** (via subprocess) |
| Tests | **pytest** + pytest-asyncio |
| CI/CD | **GitHub Actions** |
| Docs | **MkDocs Material** |

---

## Convention de code
- Tout en **français** (docstrings, logs, messages API)
- Architecture **modulaire** : chaque pilier est un package indépendant
- **Async-first** : toutes les I/O sont asynchrones
- **API-first** : chaque fonctionnalité exposée via l'API REST avant la CLI
- Tests unitaires obligatoires pour le core et les modules critiques
