# NavMAX

<div align="center">

**Plateforme de cybersécurité unifiée pilotable par agents IA**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-71%2F71-brightgreen.svg)](tests/)

*Scanner réseau · Proxy web MITM · Framework d'exploitation · Moteur OSINT & Graphe*

</div>

---

## 🎯 Vision

NavMAX combine **4 outils de cybersécurité majeurs** en une plateforme unique, conçue pour être pilotée par des **agents IA** via API REST, SDK Python, ou CLI.

| Pilier | Équivalent | Fonction |
|--------|-----------|----------|
| 🔍 **Scanner** | Nmap | TCP Connect / SYN / UDP, détection de services, fingerprinting OS |
| 🌐 **Proxy** | Burp Suite | MITM HTTP/HTTPS, interception, repeater, scanner web, fuzzer |
| 💣 **Exploit** | Metasploit | Framework d'exploits, générateur de payloads, handler, post-exploitation |
| 🕸️ **OSINT** | Maltego | DNS, WHOIS, SSL, web scraping, moteur de graphe, transforms |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  AGENT SDK / CLI                 │
│  Python async · API REST · WebSocket            │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│              API GATEWAY (FastAPI)               │
│  Auth · Rate Limit · Structured Logging          │
└────┬──────────┬──────────┬──────────┬───────────┘
     │          │          │          │
┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼────────┐
│ SCANNER │ │  PROXY │ │ EXPLOIT│ │   OSINT    │
│ (Nmap)  │ │ (Burp) │ │ (MSF)  │ │ (Maltego)  │
└────┬────┘ └───┬────┘ └───┬────┘ └─────┬──────┘
     │          │          │            │
┌────▼──────────▼──────────▼────────────▼──────┐
│           SQLite / PostgreSQL                 │
│  Targets · Scans · Vulns · Graph · Sessions   │
└──────────────────────────────────────────────┘
```

---

## 📦 Installation

```bash
# Cloner le repo
git clone https://github.com/7ShIkI3/NavMAX.git
cd NavMAX

# Installer avec uv (recommandé)
uv pip install -e .

# Ou avec pip
pip install -e .
```

**Dépendances** : Python 3.11+, FastAPI, SQLAlchemy (async), structlog, cryptography, NetworkX, Scapy, httpx, Typer.

---

## 🚀 Utilisation rapide

### Scanner réseau (Nmap-like)

```bash
# Scan TCP des 500 premiers ports
navmax scan 192.168.1.1 -p 1-500

# Scan custom
navmax scan 10.0.0.0/24 -p 22,80,443,8080,8443 -t 0.5 -c 200
```

### Investigation OSINT (Maltego-like)

```bash
# Investigation complète (DNS + WHOIS + SSL + Web → Graphe)
navmax osint example.com --depth 2

# Collecteurs individuels
navmax dns example.com
navmax whois example.com
navmax cert example.com
```

### Proxy MITM (Burp-like)

```bash
# Démarrer le proxy en mode transparent
navmax proxy -p 8080

# Avec interception active
navmax proxy -p 8080 --intercept
```

### Scanner web + Fuzzer

```bash
# Scanner de vulnérabilités web
navmax webscan http://target.com/page?id=1

# Fuzzer paramétrique
navmax fuzz http://target.com/search?q=test -c xss,sqli,path_traversal -j 10
```

### Exploitation (Metasploit-like)

```bash
# Catalogue d'exploits
navmax exploits --search eternal

# Vérifier une cible
navmax check ftp_anonymous_login -r 192.168.1.10

# Générer un payload
navmax payload -t reverse_shell -f python -h 10.0.0.1 -p 4444
navmax payload -t reverse_shell -f powershell -h 10.0.0.1 -e base64

# Lancer un listener
navmax listener -p 4444
```

### API REST

```bash
# Démarrer le serveur
navmax serve -p 8443

# Health check
curl http://127.0.0.1:8443/api/v1/health

# Documentation interactive
open http://127.0.0.1:8443/docs
```

---

## 🔌 API REST — endpoints

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/v1/targets/` | Créer une cible |
| `GET`  | `/api/v1/targets/` | Lister les cibles |
| `POST` | `/api/v1/scans/` | Lancer un scan réseau |
| `GET`  | `/api/v1/scans/{id}` | Résultat d'un scan |
| `POST` | `/api/v1/proxy/start` | Démarrer le proxy MITM |
| `POST` | `/api/v1/proxy/scan` | Scanner web une URL |
| `POST` | `/api/v1/proxy/fuzz` | Fuzzer une URL |
| `GET`  | `/api/v1/exploit/search` | Rechercher des exploits |
| `POST` | `/api/v1/exploit/run` | Exécuter un exploit |
| `POST` | `/api/v1/exploit/payload/generate` | Générer un payload |
| `POST` | `/api/v1/exploit/handler/start` | Démarrer un listener |
| `GET`  | `/api/v1/osint/dns/{domain}` | Résolution DNS |
| `GET`  | `/api/v1/osint/whois/{domain}` | WHOIS |
| `POST` | `/api/v1/osint/investigate` | Investigation complète + graphe |

---

## 🐍 SDK Python

```python
import asyncio
from navmax.sdk import NavMAXClient

async def main():
    async with NavMAXClient("http://127.0.0.1:8443") as client:
        # Créer une cible et lancer un scan
        target = await client.create_target("Serveur DMZ", "192.168.1.10")
        scan = await client.scan(target["id"], ports="22,80,443,8080")
        print(scan["result_summary"])
        # → "Ports scannés : 4 | Ports ouverts : 2 | OS probable : Linux (medium)"

asyncio.run(main())
```

---

## 📊 Fonctionnalités détaillées

### Scanner
- TCP Connect Scan (asynchrone, jusqu'à 200 connexions simultanées)
- Banner grabbing avec détection de 30+ services (SSH, HTTP, FTP, MySQL, Redis...)
- Fingerprinting OS par TTL ICMP et TCP
- Détection HTTP enrichie (headers, titre, serveur)

### Proxy Web
- MITM HTTPS avec certificats générés à la volée (CA auto-générée)
- Interception : pause / forward / drop / modify
- Repeater : historique des requêtes rejouées
- Scanner web : headers sécurité, XSS reflété, SQLi (error + time-based), path traversal, open redirect, information disclosure
- Fuzzer : 9 catégories × 50+ payloads (XSS, SQLi, command injection, XXE, SSTI, overflow...)

### Exploitation
- 4 exploits intégrés (EternalBlue CVE-2017-0144, SambaCry CVE-2017-7494, FTP Anon, Test)
- 6 formats de payloads (Python, Bash, PowerShell, cmd, Netcat)
- Encodeurs : Base64, URL, Hex, XOR
- Handler TCP multi-session + HTTP C2
- Post-exploitation : hashdump, system info, persistence (cron/scheduled task/service), clear logs, port forwarding

### OSINT & Graphe
- DNS : A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
- WHOIS : 20+ TLDs, parsing structuré (registrar, registrant, dates, nameservers)
- SSL : certificats X.509 (SAN, fingerprint SHA256, OCSP, validité)
- Web : 20 technologies, emails, liens externes, réseaux sociaux
- Graphe : 17 types d'entités, 27 types de relations, déduplication automatique
- 5 transforms (Domain→DNS, Domain→WHOIS, IP→SSL, Domain→Web, IP→ReverseDNS)
- Investigation multi-niveaux (depth 1-3)
- Export : JSON, Cytoscape.js, Sigma.js
- Orchestrateur automatique

---

## 🧪 Tests

```bash
# Lancer tous les tests
pytest tests/ -v

# Résultat : 71 passed
```

---

## 🛠️ Développement

```bash
# Mode développement avec auto-reload
navmax serve -p 8443 --reload

# Lancer les tests avec couverture
pytest tests/ --cov=navmax

# Linting
ruff check navmax/
```

---

## 📁 Structure

```
NavMAX/
├── navmax/
│   ├── core/          # Config, logging, plugin manager
│   ├── db/            # SQLAlchemy models (async)
│   ├── api/           # FastAPI + routes REST
│   ├── scanner/       # Scanner réseau (Nmap-like)
│   ├── proxy/         # Proxy MITM + scanner web + fuzzer
│   ├── exploit/       # Framework d'exploitation
│   ├── osint/         # Collecteurs + graphe + transforms
│   │   ├── collectors/  # DNS, WHOIS, SSL, Web
│   │   └── graph/       # NetworkX engine, entités, transforms
│   └── sdk/           # Client Python asynchrone
├── tests/             # 71 tests unitaires
├── pyproject.toml
└── PLAN.md            # Feuille de route
```

---

## 📄 License

MIT © Raphaël Pascaud

---

<div align="center">

**NavMAX** — *For AI agents, by an AI agent* 🤖

</div>
