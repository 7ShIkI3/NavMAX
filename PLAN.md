# NavMAX — Plan d'Architecture & Développement

## Vision
Plateforme de cybersécurité unifiée **pilotable par des agents IA**, combinant :
- 🔍 **Nmap** → Reconnaissance réseau
- 🌐 **Burp Suite** → Analyse & interception web
- 💣 **Metasploit** → Exploitation & post-exploitation
- 🕸️ **Maltego** → OSINT & graphe de relations

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
└────┬────┘ └───┬────┘ └───┬────┘ └─────┬──────┘
     │          │          │            │
┌────▼──────────▼──────────▼────────────▼──────┐
│              CORE DATABASE                     │
│  Targets · Vulns · Creds · Graph · Logs        │
│  SQLite (dev) → PostgreSQL (prod)              │
└────────────────────────────────────────────────┘
```

---

## Ordre de Développement (justifié)

### Phase 1 — FONDATIONS (Core + Scanner Nmap)
**Pourquoi d'abord :** La reconnaissance réseau est le point d'entrée de toute opération cyber. C'est le plus autonome (pas besoin des autres modules) et pose l'infrastructure (API, DB, plugin system).

| Étape | Composant |
|-------|-----------|
| 1.1 | Core Engine : config, logging, plugin loader |
| 1.2 | Base de données : SQLAlchemy models (targets, scans, services) |
| 1.3 | API REST FastAPI : endpoints CRUD + scan |
| 1.4 | Module Scanner : TCP connect, SYN (admin), UDP, service detection |
| 1.5 | Fingerprinting : banners, OS detection TTL/TCP stack |
| 1.6 | Agent SDK Python : client asynchrone |

### Phase 2 — INTERCEPTION WEB (Proxy Burp)
**Pourquoi 2e :** Après avoir découvert des services, on analyse les applications web. Le proxy intercepte le trafic entre l'agent IA et la cible.

| Étape | Composant |
|-------|-----------|
| 2.1 | Proxy HTTP/HTTPS : MITM avec cert auto-générée |
| 2.2 | Interception : pause/modify/forward requests |
| 2.3 | Repeater : rejouer des requêtes modifiées |
| 2.4 | Scanner web : XSS, SQLi, CSRF, path traversal |
| 2.5 | Fuzzer : injection paramètres, headers, body |

### Phase 3 — EXPLOITATION (Metasploit-like)
**Pourquoi 3e :** Une fois les vulnérabilités identifiées (via Scanner + Proxy), on passe à l'exploitation.

| Étape | Composant |
|-------|-----------|
| 3.1 | Module d'exploit : format standard (comme MSF modules) |
| 3.2 | Payloads : reverse shell, bind shell, meterpreter-like |
| 3.3 | Handler : listener multi-protocole (TCP, HTTP, DNS) |
| 3.4 | Base d'exploits : catalogue versionné + recherche |
| 3.5 | Post-exploitation : hashdump, persistence, pivot |

### Phase 4 — OSINT & GRAPHE (Maltego-like)
**Pourquoi 4e :** L'OSINT peut tourner en continu. Le graphe unifie toutes les données des phases 1-3 + données externes.

| Étape | Composant |
|-------|-----------|
| 4.1 | Collecteurs OSINT : DNS, WHOIS, Shodan, certificats, réseaux sociaux |
| 4.2 | Moteur de graphe : NetworkX → Neo4j (entités + relations) |
| 4.3 | Transformations : entité → nouvelles entités (comme Maltego transforms) |
| 4.4 | Visualisation : export JSON → Sigma.js / Cytoscape |

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
| Tests | **pytest** + pytest-asyncio |
| Packaging | **uv** / pip |

---

## Convention de code
- Tout en **français** (docstrings, logs, messages API)
- Architecture **modulaire** : chaque pilier est un package indépendant
- **Async-first** : toutes les I/O sont asynchrones
- **API-first** : chaque fonctionnalité exposée via l'API REST avant la CLI
- Tests unitaires obligatoires pour le core et les modules critiques

---

## Prochaines actions immédiates
1. Initialiser le projet Python (structure, dépendances)
2. Coder le Core Engine (config, logging, plugin loader)
3. Coder les modèles DB (Target, Scan, Service)
4. Coder l'API REST squelette
5. Implémenter le Scanner Nmap

→ **Go Phase 1.**
