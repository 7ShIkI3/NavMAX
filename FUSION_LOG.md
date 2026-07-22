# 🜏 NavMAX × Dark Triad — Fusion Log
## Serveur : linux-node (Linux Mint 22.2, Tailscale 100.102.128.40)
## Date : 17 Juillet 2026
## Résultat : NavMAX v0.4.1 + Dark Triad v0.1.0 greffé

---

## RÉSUMÉ

NavMAX EST le vrai projet mature. TDT est un fork/spinoff qui a ajouté l'archi multi-agent.
La fusion combine le meilleur des deux : les vrais modules de NavMAX + le BattleManager Dark Triad.

---

## COMPARAISON

| Capacité | NavMAX | Dark Triad (TDT) | Fusion |
|----------|--------|-----------------|--------|
| Scanner TCP contextuel | ✅ | ❌ | ✅ |
| Nuclei 10k+ CVE | ✅ | 🟡 | ✅ |
| Proxy MITM | ✅ | ❌ | ✅ |
| Fuzzer + Intruder | ✅ | ❌ | ✅ |
| 20+ modules exploit | ✅ | ❌ | ✅ |
| AD/LDAP | ✅ | ❌ | ✅ |
| Firewall API | ✅ | ❌ | ✅ |
| OSINT + Graphe | ✅ | ❌ | ✅ |
| Payloads + Évasion | ✅ | ❌ | ✅ |
| API REST + Dashboard | ✅ | ❌ | ✅ |
| JWT + RBAC | ✅ | ❌ | ✅ |
| Cracking + Wireless | ✅ | ❌ | ✅ |
| Architecture multi-agent | ❌ | ✅ (18 agents) | ✅ |
| Personnalités Dark Triad | ❌ | ✅ (3 modes) | ✅ |
| BattleManager + déconfliction | ❌ | ✅ | ✅ |
| Planification IA par LLM | ❌ | ✅ | ✅ |
| Neo4j Knowledge Graph | ❌ | ✅ (prêt) | 🟡 |

---

## FICHIERS MODIFIÉS

### NavMAX :
| Fichier | Changement |
|---------|------------|
| `navmax/ai/engine.py` | Ajout `deepseek_base_url` depuis env var |
| `navmax/cli.py` | Ajout commande `navmax dark-triad mission` |

### Fichiers créés (Dark Triad greffon) :
| Fichier | Rôle |
|---------|------|
| `navmax/dark_triad/__init__.py` | Package init |
| `navmax/dark_triad/personality.py` | NARCISSUS/PSYCHOPATH/MACHIAVELLI |
| `navmax/dark_triad/base.py` | BaseAgent, AgentResult, AgentStep |
| `navmax/dark_triad/recon.py` | ReconAgent (nmap, dig, curl, SSL) |
| `navmax/dark_triad/exploiter.py` | ExploiterAgent (nuclei, harvest, hydra) |
| `navmax/dark_triad/post_exploit.py` | PostExploitAgent |
| `navmax/dark_triad/evader.py` | EvaderAgent |
| `navmax/dark_triad/ad_specialist.py` | ADSpecialistAgent |
| `navmax/dark_triad/registry.py` | AgentRegistry |
| `navmax/dark_triad/battle_manager.py` | BattleManager + DeconflictionEngine |
| `navmax/dark_triad/mission_planner.py` | MissionPlanner (LLM decomposition) |
| `navmax/dark_triad/shared.py` | MissionPlan, MissionPhase, PhaseResult |
| `navmax/dark_triad/ai_router.py` | AIRouter multi-provider |
| `navmax/dark_triad/tool_registry.py` | ToolRegistry |
| `navmax/dark_triad/sandbox.py` | SandboxManager |
| `navmax/dark_triad/bootstrap.py` | Bootstrap 18 agents + run_mission() |

### Config :
| Fichier | Rôle |
|---------|------|
| `~/.navmax/api_keys.yaml` | Clés API DeepSeek |
| `~/.tdt/providers.json` | Config AI Router |

---

## BUGS CORRIGÉS

1. **bcrypt/passlib** → pin bcrypt==4.0.1
2. **Base URL DeepSeek** → lecture depuis `deepseek_base_url` dans YAML + env
3. **Format api_keys.yaml** → structure `providers:` attendue
4. **Imports TDT→NavMAX** → 14 fichiers adaptés

---

## COMMANDES

```bash
# NavMAX classique
navmax scan 127.0.0.1 -p 22,80,443,3333,5678,8443,8083 --contextual
navmax osint example.com
navmax exploits
navmax fuzz http://target/

# API + Dashboard (JWT)
NAVMAX_JWT_SECRET="xxx" navmax serve --host 127.0.0.1 --port 8444

# Dark Triad multi-agent
navmax dark-triad mission "Audit complet de 127.0.0.1" --persona mach
navmax dark-triad mission "Test d'intrusion" --persona narcissism
navmax dark-triad mission "Attaque furtive" --persona psychopathy
```

---

## PROCHAINES ÉTAPES

1. Corriger le deadlock dans BattleManager (phases dépendantes bloquées si parent fails)
2. Intégrer NavMAX Scanner dans ReconAgent (remplacer nmap par le scanner contextuel)
3. Activer Neo4j Knowledge Graph pour stocker les findings
4. Exposer `/api/v1/dark-triad/missions` dans l'API REST
5. Connecter le Dashboard NavMAX au BattleManager
