# Rapport d'Analyse de Couverture de Tests — NavMAX

**Projet :** NavMAX v0.4.1  
**Tests exécutés :** 772 passed, 45 skipped (pytest)  
**Date :** 26 juin 2026  
**Source :** `navmax/` (145 fichiers .py)  
**Tests :** `tests/` (27 fichiers test_*.py — 805 fonctions `def test_`)

---

## 1. Vue d'ensemble — Tests par fichier

| Fichier de test | # tests | Statut |
|---|---|---|
| `test_ad.py` | 119 | ✅ |
| `test_intruder.py` | 64 | ✅ |
| `test_plugin_manager.py` | 52 | ✅ |
| `test_react_agent.py` | 44 | ✅ |
| `test_auth.py` | 43 | ✅ |
| `test_cloud.py` | 41 | ✅ |
| `test_scanner_contextual.py` | 41 | ✅ |
| `test_ai.py` | 39 | ✅ |
| `test_p5_p6.py` | 33 | ✅ |
| `test_reporting.py` | 30 | ✅ |
| `test_nuclei_scanner.py` | 30 | ✅ |
| `test_firewall.py` | 23 | ⚠️ |
| `test_exploit.py` | 23 | ⚠️ |
| `test_mitm.py` | **22 (skip global ❌)** | ⚠️ → ❌ |
| `test_osint_monitor.py` | 21 | ⚠️ |
| `test_tasks.py` | **21 (skip global ❌)** | ⚠️ → ❌ |
| `test_infrastructure.py` | 19 | ⚠️ |
| `test_osint.py` | 19 | ⚠️ |
| `test_mission_planner.py` | 18 | ⚠️ |
| `test_nmap_scanner.py` | 18 | ⚠️ |
| `test_reporting_integrations.py` | 17 | ⚠️ |
| `test_core.py` | 16 | ⚠️ |
| `test_proxy.py` | 13 | ⚠️ |
| `test_playwright_spider.py` | 13 | ⚠️ |
| `test_audit.py` | 10 | ⚠️ |
| `test_workspace.py` | 10 | ⚠️ |
| `test_sandbox.py` | 6 | ⚠️ |
| **Total** | **805** | |

**Légende statut :** ✅ ≥10 | ⚠️ 1-9 | ❌ 0 (effectif après skip)

---

## 2. Couverture par module source

### 2.1 `navmax/core/` — Core

| Module | Tests | Statut |
|---|---|---|
| `core/audit.py` | 10 (test_audit.py) | ⚠️ |
| `core/config.py` | 2 (test_core.py) | ⚠️ |
| `core/constants.py` | **0** | ❌ |
| `core/exceptions.py` | **0** | ❌ |
| `core/logging.py` | **0** | ❌ |
| `core/plugin_manager.py` | 52 (test_plugin_manager.py) | ✅ |
| `core/plugins.py` | 52 (covers via test_plugin_manager) | ✅ |
| `core/retry.py` | **0** | ❌ |
| `core/task_manager.py` | **0** | ❌ |
| `core/utils.py` | **0** | ❌ |

**Total core :** 6/10 modules testés — 4 sans aucun test

### 2.2 `navmax/scanner/` — Scanner réseau

| Module | Tests | Statut |
|---|---|---|
| `scanner/contextual.py` | 41 (test_scanner_contextual.py) | ✅ |
| `scanner/engine.py` | 2 (test_core.py — parse_ports) | ⚠️ |
| `scanner/fingerprint.py` | **0** | ❌ |
| `scanner/nmap_scanner.py` | 18 (test_nmap_scanner.py) | ⚠️ |
| `scanner/nuclei_scanner.py` | 30 (test_nuclei_scanner.py) | ✅ |
| `scanner/tcp.py` | 3 (test_core.py — _parse_banner) | ⚠️ |
| `scanner/vuln_db.py` | **0** | ❌ |

**Total scanner :** 5/7 modules testés — 2 sans test

### 2.3 `navmax/proxy/` — Proxy MITM

| Module | Tests | Statut |
|---|---|---|
| `proxy/certs.py` | 2 (test_proxy.py) | ⚠️ |
| `proxy/crawler.py` | **0** | ❌ |
| `proxy/fuzzer.py` | 2 (test_proxy.py) | ⚠️ |
| `proxy/interceptor.py` | 4 (test_proxy.py) | ⚠️ |
| `proxy/intruder.py` | 64 (test_intruder.py) | ✅ |
| `proxy/mitm.py` | **22 skip global** → 0 effectif | ❌ |
| `proxy/playwright_spider.py` | 13 (test_playwright_spider.py) | ⚠️ |
| `proxy/proxy_server.py` | **0** | ❌ |
| `proxy/repeater.py` | 2 (test_proxy.py) | ⚠️ |
| `proxy/scanner.py` | 1 (test_proxy.py, skippé) → 0 | ❌ |
| `proxy/structural_fuzzer.py` | **0** | ❌ |

**Total proxy :** 6/11 modules testés — 5 sans test effectif

### 2.4 `navmax/exploit/` — Exploitation

| Module | Tests | Statut |
|---|---|---|
| `exploit/__init__.py` | ~23 (test_exploit.py) | ✅ |
| `exploit/ai_generator.py` | ~10 (test_p5_p6.py) | ⚠️ |
| `exploit/auto_pivot.py` | ~8 (test_p5_p6.py) | ⚠️ |
| `exploit/database.py` | **0** | ❌ |
| `exploit/encoders.py` | **0** | ❌ |
| `exploit/evasion.py` | ~8 (test_p5_p6.py) | ⚠️ |
| `exploit/handler.py` | ~3 (test_exploit.py) | ⚠️ |
| `exploit/module.py` | ~7 (test_exploit.py) | ⚠️ |
| `exploit/modules/*` (20 modules) | **0 individuellement** | ❌ |
| `exploit/payloads.py` | ~7 (test_exploit.py) | ⚠️ |
| `exploit/post_exploit.py` | 3 (test_exploit.py) | ⚠️ |
| `exploit/sandbox.py` | 6 (test_sandbox.py) | ⚠️ |

**Total exploit :** 8/12+ modules testés — 20 modules d'exploit individuels non testés

### 2.5 `navmax/ai/` — Intelligence Artificielle

| Module | Tests | Statut |
|---|---|---|
| `ai/engine.py` | via test_ai.py | ⚠️ |
| `ai/hardware.py` | 8 (test_ai.py) | ⚠️ |
| `ai/mission_planner.py` | 18 (test_mission_planner.py) | ⚠️ |
| `ai/models_catalog.py` | 10 (test_ai.py) | ⚠️ |
| `ai/providers/base.py` | 5 (test_ai.py) | ⚠️ |
| `ai/providers/llamacpp.py` | **0** | ❌ |
| `ai/providers/lmstudio.py` | **0** | ❌ |
| `ai/providers/ollama.py` | **0** | ❌ |
| `ai/providers/openai_compat.py` | **0** | ❌ |
| `ai/react_agent.py` | 44 (test_react_agent.py) | ✅ |
| `ai/selector.py` | 10 (test_ai.py) | ⚠️ |

**Total ai :** 7/11 modules testés — 4 providers sans test

### 2.6 `navmax/ad/` — Active Directory

| Module | Tests | Statut |
|---|---|---|
| `ad/__init__.py` | via test_ad.py | ✅ |
| `ad/adcs_scanner.py` | via test_ad.py | ✅ |
| `ad/attack_paths.py` | via test_ad.py | ✅ |
| `ad/bloodhound_export.py` | via test_infrastructure.py | ✅ |
| `ad/connector.py` | ~30 (test_ad.py) | ✅ |
| `ad/enumerator.py` | ~20 (test_ad.py) | ✅ |
| `ad/password_spray.py` | ~10 (test_ad.py) | ✅ |
| `ad/smb_scanner.py` | via test_ad.py | ✅ |
| `ad/trust_graph.py` | via test_ad.py + test_infrastructure.py | ✅ |
| `ad/vuln_scanner.py` | via test_ad.py + test_infrastructure.py | ✅ |

**Total ad :** 10/10 modules testés — ✅ Meilleure couverture du projet

### 2.7 `navmax/osint/` — OSINT

| Module | Tests | Statut |
|---|---|---|
| `osint/collectors/dns.py` | ~6 (test_osint.py) | ⚠️ |
| `osint/collectors/shodan.py` | **0** | ❌ |
| `osint/collectors/ssl.py` | **0** | ❌ |
| `osint/collectors/web.py` | **0** | ❌ |
| `osint/collectors/whois.py` | **0** | ❌ |
| `osint/graph/engine.py` | **0** | ❌ |
| `osint/graph/entities.py` | **0** | ❌ |
| `osint/graph/semantic_search.py` | **0** | ❌ |
| `osint/graph/transforms.py` | **0** | ❌ |
| `osint/monitor.py` | 21 (test_osint_monitor.py) | ✅ |
| `osint/orchestrator.py` | **0** | ❌ |

**Total osint :** 2/11 modules testés — 9 sans aucun test

### 2.8 `navmax/reporting/` — Rapports

| Module | Tests | Statut |
|---|---|---|
| `reporting/cvss_scorer.py` | ~12 (test_reporting.py) | ✅ |
| `reporting/generator.py` | ~8 (test_reporting_integrations.py) | ⚠️ |
| `reporting/sarif_exporter.py` | ~10 (test_reporting.py) | ⚠️ |
| `integrations/__init__.py` | ~4 (test_reporting_integrations.py) | ⚠️ |

**Total reporting :** 4/4 modules testés

### 2.9 `navmax/firewall/` — Firewall

| Module | Tests | Statut |
|---|---|---|
| `firewall/base.py` | ~8 (test_firewall.py) | ⚠️ |
| `firewall/correlation.py` | ~8 (test_firewall.py) | ⚠️ |
| `firewall/fortigate.py` | **0** | ❌ |
| `firewall/rule_analyzer.py` | ~5 (test_firewall.py) | ⚠️ |
| `firewall/stormshield.py` | **0** | ❌ |

**Total firewall :** 3/5 modules testés — 2 sans test

### 2.10 `navmax/api/` — API

| Module | Tests | Statut |
|---|---|---|
| `api/app.py` | **0** (via test_tasks.py skip) | ❌ |
| `api/auth.py` | 43 (test_auth.py) | ✅ |
| `api/routes/ad.py` | **0** | ❌ |
| `api/routes/ai.py` | **0** | ❌ |
| `api/routes/exploit.py` | **0** | ❌ |
| `api/routes/firewall.py` | **0** | ❌ |
| `api/routes/nuclei.py` | **0** | ❌ |
| `api/routes/osint.py` | **0** | ❌ |
| `api/routes/proxy.py` | **0** | ❌ |
| `api/routes/scans.py` | **0** | ❌ |
| `api/routes/targets.py` | **0** | ❌ |
| `api/routes/workspaces.py` | **0** | ❌ |
| `api/schemas.py` | **0** | ❌ |

**Total api :** 1/14 modules testés — 13 sans aucun test

### 2.11 Autres modules

| Module | Tests | Statut |
|---|---|---|
| `infrastructure/continuous_monitor.py` | ~5 (test_infrastructure.py) | ⚠️ |
| `infrastructure/impact_reporter.py` | ~5 (test_infrastructure.py) | ⚠️ |
| `infrastructure/remediation_advisor.py` | ~5 (test_infrastructure.py) | ⚠️ |
| `db/engine.py` | **0** | ❌ |
| `db/models.py` | 1 (test_core.py — import) | ⚠️ |
| `workspace/manager.py` | 10 (test_workspace.py) | ⚠️ |
| `cloud/scanner.py` | 41 (test_cloud.py) | ✅ |
| `orchestrator/engine.py` | ~8 (test_p5_p6.py) | ⚠️ |
| `tasks/scan_tasks.py` | **0** (skip global test_tasks.py) | ❌ |
| `sdk/client.py` | **0** | ❌ |
| `cli.py` | **0** | ❌ |

---

## 3. Modules avec 0 test (gaps critiques)

### ❌ Gaps « zéro test » — 46 fichiers source

| Package | Fichiers sans test |
|---|---|
| **core/** (4) | `constants.py`, `exceptions.py`, `logging.py`, `retry.py`, `task_manager.py`, `utils.py` |
| **scanner/** (2) | `fingerprint.py`, `vuln_db.py` |
| **proxy/** (2) | `crawler.py`, `proxy_server.py`, `structural_fuzzer.py` (+ `scanner.py` effectif) |
| **exploit/** (22) | `database.py`, `encoders.py`, + les 20 modules `modules/*.py` |
| **ai/** (4) | `providers/llamacpp.py`, `providers/lmstudio.py`, `providers/ollama.py`, `providers/openai_compat.py` |
| **osint/** (9) | `collectors/shodan.py`, `collectors/ssl.py`, `collectors/web.py`, `collectors/whois.py`, `graph/engine.py`, `graph/entities.py`, `graph/semantic_search.py`, `graph/transforms.py`, `orchestrator.py` |
| **firewall/** (2) | `fortigate.py`, `stormshield.py` |
| **api/** (13) | `app.py`, `routes/ad.py`, `routes/ai.py`, `routes/exploit.py`, `routes/firewall.py`, `routes/nuclei.py`, `routes/osint.py`, `routes/proxy.py`, `routes/scans.py`, `routes/targets.py`, `routes/workspaces.py`, `schemas.py` |
| **infrastructure/** (2) | `__init__.py`, `impact_reporter.py`, `remediation_advisor.py` (couverts mais partiellement) |
| **db/** (2) | `engine.py`, `models.py` |
| **sdk/** (2) | `__init__.py`, `client.py` |
| **tasks/** (2) | `__init__.py`, `scan_tasks.py` |
| **Autres** | `cli.py` |

---

## 4. Modules sous-testés (< 10 tests effectifs)

| Module | Tests effectifs | Note |
|---|---|---|
| `core/config.py` | 2 | Très peu de tests |
| `scanner/engine.py` | 2 | Seulement `parse_ports` |
| `scanner/tcp.py` | 3 | Seulement `_parse_banner` |
| `proxy/certs.py` | 2 | Générateur de certificats |
| `proxy/fuzzer.py` | 2 | Fuzzer HTTP |
| `proxy/repeater.py` | 2 | Send HTTP |
| `proxy/scanner.py` | 0 (1 skippé) | WebScanner non testé |
| `proxy/mitm.py` | 0 | skip global — 22 tests non exécutés |
| `tasks/scan_tasks.py` | 0 | skip global — 21 tests non exécutés |
| `exploit/handler.py` | 3 | Handler lifecycle |
| `exploit/post_exploit.py` | 3 | Post-exploitation |
| `exploit/sandbox.py` | 6 | Docker sandbox |
| `db/models.py` | 1 | Simple import check |

---

## 5. Tests ignorés (skipped) — analyse

| Fichier | # skip | Raison | Impact |
|---|---|---|---|
| `test_mitm.py` | **22** (module-level) | `mitmproxy tests require network — skipped in dev` | **Tout le module MITM non testé** |
| `test_tasks.py` | **21** (module-level) | `Celery tests require Redis + JWT auth — skipped in dev` | **Tout le module Tasks non testé** |
| `test_proxy.py` | 1 | `Test réseau flaky — httpbin.org parfois inaccessible` | 1 test WebScanner désactivé |
| `test_plugin_manager.py` | 1 (cond.) | `symlinks not supported on this platform` | 1 test conditionnel |
| **Total** | **45** | | 43 tests non exécutés en permanence |

**Problème :** 2 fichiers complets (43 tests) sont systématiquement ignorés. Cela masque probablement des régressions.

---

## 6. Fixtures et configuration (conftest.py)

**Aucun fichier `conftest.py` trouvé** — ni à la racine du projet, ni dans `tests/`.

**Conséquences :**
- Chaque fichier de test définit ses propres fixtures (répétition de code)
- `test_workspace.py` et `test_audit.py` dupliquent la même fixture `session` SQLite en mémoire
- Pas de configuration partagée, pas de marqueurs personnalisés
- La config pytest (`pyproject.toml`) est minimale : `asyncio_mode = "auto"`, `testpaths = ["tests"]`

---

## 7. Qualité des tests — observations

### Points forts ✅
- **Module AD** : excellente couverture (119 tests, toutes les classes testées)
- **Intruder** : 64 tests, robuste
- **ReAct Agent/IA** : 44+39 tests, avec mocks bien conçus
- **Plugin Manager** : 52 tests, couvre découverte, manifestes, validation
- **Cloud Scanner** : 41 tests avec mocks HTTP/socket
- **Contextual Scanner** : 41 tests

### Points faibles ❌
- **API Routes** : aucune route FastAPI testée (13 fichiers sans test)
- **DB** : pas de test sur `engine.py` (connexion, migrations)
- **Modules d'exploit** : 20 modules individuels non testés (seulement le loader/registry)
- **Providers AI** : llama.cpp, LM Studio, Ollama, OpenAI — aucun test (seulement le `BaseProvider` protocol)
- **OSINT Graph** : tout le moteur de graphe (Neo4j) sans test
- **CLI** : aucune couverture
- **SDK Client** : aucune couverture

### Problèmes structurels
1. **Pas de conftest.py** → fixtures dupliquées, pas de configuration centralisée
2. **Skip globaux** : 43 tests (mitm, tasks) systématiquement ignorés
3. **Tests réseau dépendants** : httpbin.org (flaky), Celery/Redis
4. **Tests d'intégration manquants** : pas de test sur les routes API, pas de test E2E

---

## 8. Résumé statistique

| Métrique | Valeur |
|---|---|
| Fichiers source (navmax/) | 145 |
| Fichiers de test | 27 |
| Fonctions test | 805 |
| Tests passés | 772 |
| Tests skip | 45 |
| Taux de fichiers source avec test | ~19 % (27/145) |
| Modules avec test dédié (package) | ~55 % |
| Modules sans aucun test (fichiers) | ~46 (32 %) |
| Fixtures conftest.py | 0 |

---

## 9. Recommandations prioritaires

1. **🟥 Critiques** — Créer des tests pour :
   - Les **20 modules d'exploit individuels** (tests unitaires avec mocks)
   - Les **13 routes API** (utiliser `TestClient` FastAPI)
   - Les **providers AI** (llamacpp, ollama, lmstudio, openai)
   - Le **CLI** (test typer)

2. **🟧 Urgent** — Réactiver ou remplacer les tests skip :
   - `test_mitm.py` : créer des mocks mitmproxy
   - `test_tasks.py` : utiliser un Redis mocké (ou `fakeredis`)

3. **🟨 Important** — Ajouter un `conftest.py` :
   - Session SQLite partagée
   - Marqueurs personnalisés
   - Fixtures communes

4. **🟩 Souhaitable**
   - OSINT Graph (Neo4j mocké)
   - DB Engine (connexion, migrations)
   - SDK Client
