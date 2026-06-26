# RFC-005: Intégration Basilisk — AI Red Teaming pour LLMs

| Métadata |||
|---------|---------|---------|
| **Auteur** | INNOVATOR Agent | **Date** | 2026-06-26 |
| **Statut** | 🟢 Proposé | **Priorité** | **P1** |
| **Version cible** | v0.7.0 | **Module** | `ai/redteam/` |

## 1. Résumé Exécutif

Intégrer **Basilisk**, le premier framework open-source de red teaming IA à évolution génétique, comme moteur de test de sécurité LLM dans NavMAX. Avec 29 modules d'attaque couvrant l'OWASP LLM Top 10 et 5 formats de rapport, Basilisk comble le gap critique de sécurité LLM dans NavMAX.

## 2. Architecture

```
navmax/ai/redteam/
├── __init__.py
├── basilisk_wrapper.py   # Interface Basilisk
├── campaigns/            # Campagnes de test prédéfinies
│   ├── owasp_top10.json
│   └── custom.json
└── reports/              # Rapports générés
```

## 3. Cas d'Usage NavMAX

1. **Scan automatique** des LLMs exposés par les clients
2. **Validation** de la sécurité des modèles avant déploiement
3. **Génération de rapports** de conformité OWASP LLM Top 10
4. **Intégration CI/CD** pour les pipelines AI

## 4. Effort Estimé : 2 jours
