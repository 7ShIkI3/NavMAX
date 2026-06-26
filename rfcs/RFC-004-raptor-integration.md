# RFC-004: Intégration RAPTOR — Agent Autonome Offensif/Défensif

| Métadata |||
|---------|---------|---------|
| **Auteur** | INNOVATOR Agent | **Date** | 2026-06-26 |
| **Statut** | 🟢 Proposé | **Priorité** | **P1** |
| **Version cible** | v0.7.0 | **Module** | `ai/` + nouveau `raptor/` |

## 1. Résumé Exécutif

Intégrer **RAPTOR** (Recursive Autonomous Penetration Testing and Observation Robot) comme moteur agentique avancé dans NavMAX. RAPTOR transforme le ReAct Agent existant en un agent de sécurité véritablement autonome, capable de comprendre le code source, prouver l'exploitabilité, générer des exploits ET proposer des correctifs.

**Pourquoi maintenant** : Le ReAct Agent de NavMAX est fonctionnel mais basique (planification → exécution → rapport). RAPTOR ajoute une couche de raisonnement profond, analyse de code, et génération de patches qui manque cruellement.

## 2. Architecture Technique

```
┌────────────────────────────────────────────────┐
│                   NavMAX                        │
│  ┌─────────────┐    ┌──────────────────────┐   │
│  │ ReAct Agent  │───▶│   RAPTOR Bridge     │   │
│  │ (existant)   │    │  (raptor_bridge.py)  │   │
│  └─────────────┘    └──────────┬───────────┘   │
│                                │                │
│  ┌─────────────────────────────▼────────────┐  │
│  │         RAPTOR Engine                    │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ │  │
│  │  │ Recon    │ │ Exploit  │ │ Patch    │ │  │
│  │  │ Agent    │ │ Agent    │ │ Agent    │ │  │
│  │  └──────────┘ └──────────┘ └──────────┘ │  │
│  └──────────────────────────────────────────┘  │
│                                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ Nuclei   │ │ Exploit  │ │ Cloud        │   │
│  │ Scanner  │ │ Engine   │ │ Scanner      │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
└────────────────────────────────────────────────┘
```

## 3. Implémentation

### Fichiers à créer
- `navmax/ai/raptor_bridge.py` — Pont principal
- `navmax/ai/raptor_skills/` — Sous-agents RAPTOR
- `navmax/raptor/CLAUDE.md` — Configuration RAPTOR NavMAX

### Dépendances
- Claude Code (ou API Anthropic)
- Git (pour RAPTOR clone)
- Python 3.11+

### Installation
```bash
cd $NAVMAX_ROOT
git clone https://github.com/gadievron/raptor.git navmax/ai/raptor
pip install -r navmax/ai/raptor/requirements.txt
```

## 4. Risques et Mitigations

| Risque | Mitigation |
|--------|------------|
| Dépendance à Claude Code | Support multi-providers via `ai/providers/` existant |
| Consommation API élevée | Rate limiting, cache des résultats |
| Sécurité (agent exécute code) | Sandbox Docker existante, validation pré-exécution |

## 5. Effort Estimé : 3 jours

- Jour 1 : Bridge RAPTOR-NavMAX (cli → API)
- Jour 2 : Intégration sous-agents dans le pipeline NavMAX
- Jour 3 : Tests, documentation, hook dans le dashboard
