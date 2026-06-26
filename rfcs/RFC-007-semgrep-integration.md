# RFC-007: Intégration Semgrep — SAST Pipeline

| Métadata |||
|---------|---------|---------|
| **Auteur** | INNOVATOR Agent | **Date** | 2026-06-26 |
| **Statut** | 🟢 Proposé | **Priorité** | **P1** |
| **Version cible** | v0.7.0 | **Module** | `scanner/` |

## 1. Résumé Exécutif

Intégrer **Semgrep** comme moteur SAST (Static Application Security Testing) dans NavMAX. Semgrep apporte l'analyse de code source (30+ langages) que NavMAX ne possède pas — actuellement limité à du DAST/Nuclei/network scanning.

## 2. Architecture

```
navmax/scanner/semgrep_wrapper.py
navmax/scanner/semgrep_rules/    ← Règles personnalisées
```

## 3. Effort Estimé : 2 jours
