# RFC-006: Intégration EscalateGPT — Cloud IAM Privilege Escalation

| Métadata |||
|---------|---------|---------|
| **Auteur** | INNOVATOR Agent | **Date** | 2026-06-26 |
| **Statut** | 🟢 Proposé | **Priorité** | **P1** |
| **Version cible** | v0.7.0 | **Module** | `cloud/` |

## 1. Résumé Exécutif

Intégrer **EscalateGPT** (Tenable) au module `cloud/` pour ajouter une capacité de détection IA des chemins d'escalade de privilèges IAM dans AWS et Azure. Complète le IAM analyzer existant avec une couche d'IA prédictive.

## 2. Architecture

```
navmax/cloud/escalate_gpt_bridge.py
navmax/cloud/iam_analyzer.py  ← enrichi
```

## 3. Effort Estimé : 2 jours
