# Rapport d'Audit Architectural — Modules v0.6.0

**Date :** 26 juin 2026  
**Rôle :** ARCHITECTE (agent-structure-manager)  
**Périmètre :** Modules cracking/, wireless/, web/, ad/ (wrappers v0.6.0) + tests associés  
**Tests :** 216 tests au total (cracking 103 + wireless 47 + web 29 + AD 37)

---

## Résumé par module

| Module | Fichiers | Tests | Conformité |
|--------|----------|-------|------------|
| `cracking/` | 6 fichiers + data/ | 103 tests (38+65) | ⚠️ 2 non-conformités |
| `wireless/` | 3 fichiers | 47 tests | ⚠️ 2 non-conformités |
| `web/` | 2 fichiers | 29 tests | ❌ 4 non-conformités |
| `ad/` (wrappers) | 2 fichiers | 37 tests | ❌ 4 non-conformités |

---

## 1. Pattern Base → Connector → Analyzer

### ✅ cracking/ — CONFORME
- `BaseCracker` (ABC dans `base.py`) : ✅ classe abstraite avec `@abstractmethod` pour `get_version()` et `crack()`
- `HashcatWrapper(BaseCracker)` : ✅ implémentation concrète de hashcat
- `JohnWrapper(BaseCracker)` : ✅ implémentation concrète de John the Ripper
- `HydraWrapper(BaseCracker)` : ✅ implémentation concrète de Hydra

### ✅ wireless/ — CONFORME
- `BaseWirelessScanner` (ABC dans `base.py`) : ✅ classe abstraite avec `@abstractmethod` pour `check_hardware()` et `scan()`
- `WiFiScanner(BaseWirelessScanner)` : ✅ implémentation concrète WiFi
- `BLEScanner(BaseWirelessScanner)` : ✅ implémentation concrète BLE

### ⚠️ web/ — NON CONFORME
- **Absence de classe de base abstraite** ❌ — `SQLMapWrapper` et `FfufWrapper` sont des classes concrètes sans héritage d'une ABC commune
- Les deux wrappers partagent pourtant la même structure (vérification installation, build_args async, parsing output) — un `BaseWebWrapper(ABC)` serait bénéfique

### ⚠️ ad/ (wrappers) — NON CONFORME
- **Absence de classe de base abstraite** ❌ — `CertipyWrapper` et `ResponderWrapper` sont des classes concrètes sans héritage d'une ABC commune
- Ces wrappers complètent le module AD existant mais n'ont pas de contrat d'interface formel

---

## 2. Structure des packages

### ✅ __init__.py — CONFORME
- `cracking/__init__.py` : ✅ exports propres avec `__all__` explicite
- `wireless/__init__.py` : ✅ exports propres avec `__all__` explicite
- `web/__init__.py` : ✅ exports propres avec `__all__` explicite
- `ad/__init__.py` : ✅ exports propres avec `__all__` (déjà existant, mis à jour pour inclure les nouveaux wrappers)
- `cracking/data/__init__.py` : ✅ exports propres

### ❌ Imports absolus (from navmax.xxx) — VIOLATION GÉNÉRALISÉE

Tous les nouveaux modules utilisent des imports absolus interdits :

| Fichier | Import absolu | Correction requise |
|---------|--------------|-------------------|
| `cracking/hashcat_wrapper.py:17` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |
| `cracking/john_wrapper.py:16` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |
| `cracking/hydra_wrapper.py:16` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |
| `cracking/library.py:20` | `from navmax.cracking.data import ...` | `from .data import ...` |
| `wireless/wifi_scanner.py:24-31` | `from navmax.core.logging` + `from navmax.wireless.base` | `from ..core.logging` + `from .base` |
| `wireless/ble_scanner.py:17-18` | `from navmax.core.logging` + `from navmax.wireless.base` | `from ..core.logging` + `from .base` |
| `web/sqlmap_wrapper.py:28` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |
| `web/ffuf_wrapper.py:25` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |
| `ad/certipy_wrapper.py:37` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |
| `ad/responder_wrapper.py:27` | `from navmax.core.logging import get_logger` | `from ..core.logging import get_logger` |

### ❌ `from __future__ import annotations` — ABSENT DANS LA PLUPART DES FICHIERS

| Fichier | Présent ? |
|---------|-----------|
| `cracking/base.py` | ❌ |
| `cracking/hashcat_wrapper.py` | ❌ |
| `cracking/john_wrapper.py` | ❌ |
| `cracking/hydra_wrapper.py` | ❌ |
| `cracking/library.py` | ✅ |
| `cracking/data/__init__.py` | ❌ |
| `wireless/base.py` | ❌ |
| `wireless/wifi_scanner.py` | ❌ |
| `wireless/ble_scanner.py` | ✅ |
| `web/sqlmap_wrapper.py` | ✅ |
| `web/ffuf_wrapper.py` | ❌ |
| `ad/certipy_wrapper.py` | ❌ |
| `ad/responder_wrapper.py` | ❌ |

### ✅ Pas d'imports circulaires détectés

---

## 3. Modèles Pydantic

### ✅ Modèles conformes (BaseModel)
| Fichier | Modèle | Type |
|---------|--------|------|
| `cracking/base.py` | `HashInfo`, `CrackResult` | ✅ `BaseModel` avec `Field()` |
| `cracking/library.py` | `WordlistInfo`, `RuleInfo`, `MaskInfo` | ✅ `BaseModel` avec `Field(description=)` |
| `wireless/base.py` | `HardwareCapability`, `WiFiNetwork`, `BLEDevice`, `Handshake` | ✅ `BaseModel` avec `Field()` |
| `cracking/base.py` | `CrackStatus`, `HashType` | ✅ `StrEnum` (correct pour énumérations) |
| `wireless/base.py` | `WirelessTech` | ✅ `StrEnum` |

### ❌ Modèles non conformes (dataclass au lieu de BaseModel)
| Fichier | Modèle | Problème |
|---------|--------|----------|
| `cracking/hydra_wrapper.py:61` | `HydraLogin` | ❌ `@dataclass` standard → doit être `BaseModel` |
| `web/sqlmap_wrapper.py:81-124` | `SqlmapStatus`, `SqlmapResult` | ❌ `@dataclass` standard → doit être `BaseModel` |
| `web/ffuf_wrapper.py:85-151` | `FfufEntry`, `FfufInput`, `FfufResult` | ❌ `@dataclass` standard → doit être `BaseModel` |
| `ad/certipy_wrapper.py:45-82` | `CertipyFinding`, `CertipyCertInfo` | ❌ `@dataclass` standard → doit être `BaseModel` |
| `ad/responder_wrapper.py:35-82` | `NTLMHash`, `ResponderStatus` | ❌ `@dataclass` standard → doit être `BaseModel` |

**Rappel :** `@dataclass` ne fournit pas la validation automatique, la documentation via `Field(description=)`, ni la sérialisation JSON native offertes par `BaseModel` Pydantic.

### ✅ Types stricts
- L'utilisation de `Any` est limitée à `**options: Any` pour les kwargs de pass-through vers subprocess — usage justifié ✅
- Pas de `Any` non justifié dans les modèles de données

---

## 4. Logging

### ✅ Modules utilisant structlog correctement
- `cracking/hashcat_wrapper.py` : ✅ `from navmax.core.logging import get_logger`
- `cracking/john_wrapper.py` : ✅ `from navmax.core.logging import get_logger`
- `cracking/hydra_wrapper.py` : ✅ `from navmax.core.logging import get_logger`
- `wireless/wifi_scanner.py` : ✅ `from navmax.core.logging import get_logger`
- `wireless/ble_scanner.py` : ✅ `from navmax.core.logging import get_logger`
- `web/sqlmap_wrapper.py` : ✅ `from navmax.core.logging import get_logger`
- `web/ffuf_wrapper.py` : ✅ `from navmax.core.logging import get_logger`
- `ad/certipy_wrapper.py` : ✅ `from navmax.core.logging import get_logger`
- `ad/responder_wrapper.py` : ✅ `from navmax.core.logging import get_logger`

### ❌ Module non conforme
- **`cracking/library.py:32`** : ❌ Utilise `logging.getLogger("navmax.cracking.library")` au lieu de structlog
  - Correction : `from ..core.logging import get_logger` puis `logger = get_logger(__name__)`

### ✅ Aucun `print()` détecté dans le code source des nouveaux modules

---

## 5. Tests

### ✅ test_cracking.py (38 tests) — CONFORME
- `@pytest.mark.asyncio` + `async def` pour les tests async ✅
- `AsyncMock`, `MagicMock`, `patch` de `unittest.mock` ✅
- Tests de modèles Pydantic ✅
- Tests de détection de hash ✅
- Tests de parsing de sortie ✅
- Fixtures avec `tmp_path` ✅

### ✅ test_wireless.py (47 tests) — CONFORME
- `from __future__ import annotations` ✅
- `@pytest.mark.asyncio` + `async def` pour les tests async ✅
- `AsyncMock`, `MagicMock`, `patch` de `unittest.mock` ✅
- Mocks de `subprocess.run`, `subprocess.Popen` ✅
- Tests de parsing CSV airodump ✅
- Tests BLE avec mocks bleak ✅

### ✅ test_cracking_library.py (65 tests) — CONFORME
- `from __future__ import annotations` ✅
- Tests synchrones uniquement (pas d'async nécessaire) ✅
- Tests de génération de wordlist ✅
- Tests d'accès aux ressources ✅

### ⚠️ test_web_wrappers.py (29 tests) — NON CONFORME
- **Aucun `@pytest.mark.asyncio`** ❌
- Utilise `asyncio.run()` dans des tests synchrones plutôt que `async def test_...` ❌
- **Aucun mock d'appels réseau** ❌ — les tests `test_execute_with_missing_wordlist` et `test_execute_fails_without_binary` testent les cas d'erreur sans mocker le binaire
- Tests de parsing JSON et modèles de données ✅
- Recommandation : migrer vers `@pytest.mark.asyncio` + `async def` + `AsyncMock`

### ⚠️ test_ad_wrappers.py (37 tests) — NON CONFORME
- **Aucun `@pytest.mark.asyncio`** ❌
- Utilise `asyncio.run()` dans des tests synchrones ❌
- **Aucun mock d'appels subprocess** ❌ — les tests utilisent des fichiers JSON simulés sur disque mais n'interceptent pas `create_subprocess_exec`
- Tests de parsing JSON et classification ESCx ✅
- Recommandation : migrer vers `@pytest.mark.asyncio` + `async def` + mocker `create_subprocess_exec`

---

## 6. Problèmes supplémentaires détectés

### ⚠️ `asyncio.run()` dans des méthodes synchrones
- `cracking/hashcat_wrapper.py:99` : `get_version()` utilise `asyncio.run()` — acceptable dans une méthode sync, mais attention aux event loops imbriquées si appelé depuis un contexte async
- `cracking/john_wrapper.py:72,86` : même pattern
- `cracking/hydra_wrapper.py:112` : même pattern

### ⚠️ Absence de ABC dans web/ et ad/ wrappers
- `SQLMapWrapper`, `FfufWrapper`, `CertipyWrapper`, `ResponderWrapper` n'héritent d'aucune classe abstraite
- Conséquence : pas de contrat d'interface formel, pas de garantie que les méthodes requises soient implémentées

---

## Tableau récapitulatif

| Critère | cracking | wireless | web | ad wrappers |
|---------|----------|----------|-----|-------------|
| Base ABC | ✅ | ✅ | ❌ | ❌ |
| __init__.py propre | ✅ | ✅ | ✅ | ✅ |
| Imports relatifs | ❌ | ❌ | ❌ | ❌ |
| `from __future__ import annotations` | ❌ 4/5 | ❌ 2/3 | ❌ 1/2 | ❌ 0/2 |
| Modèles Pydantic (pas dataclass) | ⚠️ 1 ❌ | ✅ | ❌ 2 modèles | ❌ 2 modèles |
| `Field(description=)` | ✅ | ✅ | N/A (dataclass) | N/A (dataclass) |
| Types stricts (pas de Any abusif) | ✅ | ✅ | ✅ | ✅ |
| structlog (pas logging/print) | ⚠️ library ❌ | ✅ | ✅ | ✅ |
| Tests avec pytest-asyncio | ✅ | ✅ | ❌ | ❌ |
| Tests mockent subprocess/réseau | ✅ | ✅ | ⚠️ partiel | ⚠️ partiel |
| Tests existent pour chaque module | ✅ | ✅ | ✅ | ✅ |

---

## Recommandations

### Priorité Haute
1. **Remplacer les `@dataclass` par Pydantic `BaseModel`** dans hydra_wrapper, sqlmap_wrapper, ffuf_wrapper, certipy_wrapper, responder_wrapper — 7 modèles à migrer
2. **Ajouter `from __future__ import annotations`** dans tous les fichiers des nouveaux modules (9 fichiers)
3. **Corriger le logging de `library.py`** : remplacer `logging.getLogger()` par structlog via `get_logger()`

### Priorité Moyenne
4. **Migrer les imports absolus en imports relatifs** — utiliser `from ..core.logging import get_logger` au lieu de `from navmax.core.logging import get_logger` (10 occurrences)
5. **Ajouter une classe de base abstraite** pour les wrappers web (`BaseWebWrapper`) et AD (`BaseADWrapper`) pour formaliser le contrat d'interface
6. **Migrer les tests web et AD** vers `@pytest.mark.asyncio` + `async def` + mocks asynchrones

### Priorité Faible
7. **Ajouter des tests mockant `create_subprocess_exec`** dans `test_ad_wrappers.py` pour les méthodes async de CertipyWrapper et ResponderWrapper
8. **Ajouter `Field(description=)`** sur les modèles Pydantic qui en manquent (notamment les champs simples)
