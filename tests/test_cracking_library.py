"""Tests pour CrackingLibrary — gestionnaire de bibliothèque de cracking.

Teste :
- list_wordlists / list_rules / list_masks
- get_wordlist_path / get_rule_path / get_mask_path
- search_wordlists
- generate_wordlist depuis un template
- Modèles Pydantic (WordlistInfo, RuleInfo, MaskInfo)
- install_rockyou (simulé)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from navmax.cracking import CrackingLibrary, MaskInfo, RuleInfo, WordlistInfo
from navmax.cracking.data import (
    BUILTIN_MASKS,
    BUILTIN_RULES,
    BUILTIN_WORDLISTS,
    MASKS_DIR,
    RULES_DIR,
    WORDLISTS_DIR,
    get_mask_path,
    get_rule_path,
    get_wordlist_path,
)


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def lib() -> CrackingLibrary:
    """Instance du gestionnaire (les méthodes sont statiques, mais pour la forme)."""
    return CrackingLibrary()


# ══════════════════════════════════════════════════════════════════════════════
# Tests — data/__init__.py (fonctions d'accès direct)
# ══════════════════════════════════════════════════════════════════════════════


class TestDataAccess:
    """Tests des fonctions d'accès direct dans data/__init__.py."""

    def test_get_rule_path_best64(self) -> None:
        path = get_rule_path("best64")
        assert path.exists()
        assert path.name == "best64.rule"
        assert path.parent == RULES_DIR

    def test_get_rule_path_leetspeak(self) -> None:
        path = get_rule_path("leetspeak")
        assert path.exists()
        assert path.name == "leetspeak.rule"

    def test_get_rule_path_not_found(self) -> None:
        with pytest.raises(KeyError, match="introuvable"):
            get_rule_path("nonexistent_rule")

    def test_get_wordlist_path_common(self) -> None:
        path = get_wordlist_path("common-1000")
        assert path.exists()
        assert path.name == "common-1000.txt"
        assert path.parent == WORDLISTS_DIR

    def test_get_wordlist_path_french(self) -> None:
        path = get_wordlist_path("french-common")
        assert path.exists()
        assert path.name == "french-common.txt"

    def test_get_wordlist_path_not_found(self) -> None:
        with pytest.raises(KeyError, match="introuvable"):
            get_wordlist_path("nonexistent_wordlist")

    def test_get_mask_path_common(self) -> None:
        path = get_mask_path("common")
        assert path.exists()
        assert path.name == "common.hcmask"
        assert path.parent == MASKS_DIR

    def test_get_mask_path_not_found(self) -> None:
        with pytest.raises(KeyError, match="introuvable"):
            get_mask_path("nonexistent_mask")


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Wordlists
# ══════════════════════════════════════════════════════════════════════════════


class TestListWordlists:
    """Tests de list_wordlists()."""

    def test_list_returns_list(self, lib: CrackingLibrary) -> None:
        wordlists = lib.list_wordlists()
        assert isinstance(wordlists, list)

    def test_list_contains_wordlist_objects(self, lib: CrackingLibrary) -> None:
        wordlists = lib.list_wordlists()
        for wl in wordlists:
            assert isinstance(wl, WordlistInfo)
            assert wl.name
            assert wl.filename
            assert wl.path
            assert wl.description
            assert isinstance(wl.exists, bool)

    def test_list_contains_expected_entries(self, lib: CrackingLibrary) -> None:
        wordlists = lib.list_wordlists()
        names = {w.name for w in wordlists}
        for builtin in BUILTIN_WORDLISTS:
            assert builtin["name"] in names, f"Wordlist '{builtin['name']}' absente"

    def test_list_wordlists_have_correct_paths(self, lib: CrackingLibrary) -> None:
        wordlists = lib.list_wordlists()
        for wl in wordlists:
            path = Path(wl.path)
            assert path.suffix in (".txt", ".gz")
            assert wl.exists == path.exists()

    def test_common1000_size(self, lib: CrackingLibrary) -> None:
        wordlists = lib.list_wordlists()
        common = next(w for w in wordlists if w.name == "common-1000")
        assert common.word_count > 400
        assert common.size_bytes > 3000


class TestGetWordlistPath:
    """Tests de get_wordlist_path()."""

    def test_get_existing(self, lib: CrackingLibrary) -> None:
        path = lib.get_wordlist_path("common-1000")
        assert isinstance(path, Path)
        assert path.exists()
        assert path.name == "common-1000.txt"

    def test_get_french_common(self, lib: CrackingLibrary) -> None:
        path = lib.get_wordlist_path("french-common")
        assert path.exists()

    def test_get_seasonal(self, lib: CrackingLibrary) -> None:
        path = lib.get_wordlist_path("seasonal")
        assert path.exists()
        assert path.name == "seasonal.txt"

    def test_get_nonexistent(self, lib: CrackingLibrary) -> None:
        with pytest.raises(FileNotFoundError, match="introuvable"):
            lib.get_wordlist_path("__does_not_exist__")


class TestSearchWordlists:
    """Tests de search_wordlists()."""

    def test_search_by_name(self, lib: CrackingLibrary) -> None:
        results = lib.search_wordlists("french")
        assert len(results) >= 1
        assert any("french" in r.name or "français" in r.description.lower() for r in results)

    def test_search_by_description(self, lib: CrackingLibrary) -> None:
        results = lib.search_wordlists("saison")
        assert len(results) >= 1

    def test_search_by_filename(self, lib: CrackingLibrary) -> None:
        results = lib.search_wordlists("keyboard")
        assert len(results) >= 1
        assert results[0].name == "keyboard-walks"

    def test_search_no_results(self, lib: CrackingLibrary) -> None:
        results = lib.search_wordlists("xyznonexistent")
        assert len(results) == 0

    def test_search_case_insensitive(self, lib: CrackingLibrary) -> None:
        results_upper = lib.search_wordlists("SEASONAL")
        results_lower = lib.search_wordlists("seasonal")
        assert len(results_upper) == len(results_lower)

    def test_search_returns_wordlist_info(self, lib: CrackingLibrary) -> None:
        results = lib.search_wordlists("common")
        for r in results:
            assert isinstance(r, WordlistInfo)


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Règles
# ══════════════════════════════════════════════════════════════════════════════


class TestListRules:
    """Tests de list_rules()."""

    def test_list_returns_list(self, lib: CrackingLibrary) -> None:
        rules = lib.list_rules()
        assert isinstance(rules, list)

    def test_list_contains_rule_objects(self, lib: CrackingLibrary) -> None:
        rules = lib.list_rules()
        for r in rules:
            assert isinstance(r, RuleInfo)
            assert r.name
            assert r.filename
            assert r.path
            assert r.description
            assert isinstance(r.exists, bool)

    def test_list_contains_expected_entries(self, lib: CrackingLibrary) -> None:
        rules = lib.list_rules()
        names = {r.name for r in rules}
        for builtin in BUILTIN_RULES:
            assert builtin["name"] in names, f"Règle '{builtin['name']}' absente"

    def test_list_rules_have_correct_paths(self, lib: CrackingLibrary) -> None:
        rules = lib.list_rules()
        for r in rules:
            path = Path(r.path)
            assert path.suffix == ".rule"
            assert r.exists == path.exists()

    def test_rule_attributes(self, lib: CrackingLibrary) -> None:
        rules = lib.list_rules()
        for r in rules:
            assert r.rule_count >= 0
            assert r.size_bytes >= 0
            assert isinstance(r.installed, bool)

    def test_external_url_on_large_rules(self, lib: CrackingLibrary) -> None:
        rules = lib.list_rules()
        external_rules = [r for r in rules if r.external_url]
        assert len(external_rules) >= 3  # d3ad0ne, T0XlC, etc.
        for r in external_rules:
            assert r.external_url.startswith("http")


class TestGetRulePath:
    """Tests de get_rule_path()."""

    def test_get_existing(self, lib: CrackingLibrary) -> None:
        path = lib.get_rule_path("best64")
        assert isinstance(path, Path)
        assert path.exists()
        assert path.name == "best64.rule"

    def test_get_leetspeak(self, lib: CrackingLibrary) -> None:
        path = lib.get_rule_path("leetspeak")
        assert path.exists()
        assert path.suffix == ".rule"

    def test_get_append_years(self, lib: CrackingLibrary) -> None:
        path = lib.get_rule_path("append-years")
        assert path.exists()

    def test_get_prepend_special(self, lib: CrackingLibrary) -> None:
        path = lib.get_rule_path("prepend-special")
        assert path.exists()

    def test_get_nonexistent(self, lib: CrackingLibrary) -> None:
        with pytest.raises(FileNotFoundError, match="introuvable"):
            lib.get_rule_path("__does_not_exist__")


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Masques
# ══════════════════════════════════════════════════════════════════════════════


class TestListMasks:
    """Tests de list_masks()."""

    def test_list_returns_list(self, lib: CrackingLibrary) -> None:
        masks = lib.list_masks()
        assert isinstance(masks, list)

    def test_list_contains_mask_objects(self, lib: CrackingLibrary) -> None:
        masks = lib.list_masks()
        for m in masks:
            assert isinstance(m, MaskInfo)
            assert m.name
            assert m.filename
            assert m.path
            assert m.description
            assert isinstance(m.exists, bool)

    def test_list_contains_expected_entries(self, lib: CrackingLibrary) -> None:
        masks = lib.list_masks()
        names = {m.name for m in masks}
        for builtin in BUILTIN_MASKS:
            assert builtin["name"] in names, f"Masque '{builtin['name']}' absent"

    def test_list_masks_have_correct_paths(self, lib: CrackingLibrary) -> None:
        masks = lib.list_masks()
        for m in masks:
            path = Path(m.path)
            assert path.suffix == ".hcmask"
            assert m.exists == path.exists()


class TestGetMaskPath:
    """Tests de get_mask_path()."""

    def test_get_existing(self, lib: CrackingLibrary) -> None:
        path = lib.get_mask_path("common")
        assert isinstance(path, Path)
        assert path.exists()
        assert path.name == "common.hcmask"

    def test_get_nonexistent(self, lib: CrackingLibrary) -> None:
        with pytest.raises(FileNotFoundError, match="introuvable"):
            lib.get_mask_path("__does_not_exist__")


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Génération de wordlists
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateWordlist:
    """Tests de generate_wordlist()."""

    def test_generate_simple_template(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Génération avec {year:YYYY}."""
        output = tmp_path / "generated.txt"
        result = lib.generate_wordlist("MotDePasse{year:YYYY}", output)
        assert result.exists()
        content = result.read_text(encoding="utf-8")
        assert "MotDePasse2024" in content
        assert "MotDePasse2023" in content
        assert "MotDePasse1980" in content

    def test_generate_with_season(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Génération avec {season}."""
        output = tmp_path / "seasonal_gen.txt"
        result = lib.generate_wordlist("{season}2024!", output)
        assert result.exists()
        content = result.read_text(encoding="utf-8")
        assert "summer2024!" in content.lower()
        assert "winter2024!" in content.lower()

    def test_generate_with_special(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Génération avec {special}."""
        output = tmp_path / "special_gen.txt"
        result = lib.generate_wordlist("admin{special}", output)
        assert result.exists()
        content = result.read_text(encoding="utf-8")
        assert "admin!" in content
        assert "admin@" in content

    def test_generate_plain_text(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Sans template, le texte est ajouté tel quel."""
        output = tmp_path / "plain.txt"
        result = lib.generate_wordlist("password", output)
        assert result.exists()
        content = result.read_text(encoding="utf-8").strip()
        assert content == "password"

    def test_generate_with_num(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Génération avec {num:N}."""
        output = tmp_path / "num_gen.txt"
        result = lib.generate_wordlist("pass{num:5}", output)
        assert result.exists()
        content = result.read_text(encoding="utf-8")
        assert "pass0" in content
        assert "pass5" in content

    def test_generate_creates_parent_dir(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Les répertoires parents sont créés automatiquement."""
        nested = tmp_path / "sub" / "dir" / "generated.txt"
        result = lib.generate_wordlist("test", nested)
        assert result.exists()
        assert result.parent == nested.parent

    def test_generate_utf8(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Le fichier généré est en UTF-8."""
        output = tmp_path / "utf8_gen.txt"
        lib.generate_wordlist("MotDePasse{year:YYYY}", output)
        raw = output.read_bytes()
        # Vérifier que c'est de l'UTF-8 valide
        raw.decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Intégrité des données
# ══════════════════════════════════════════════════════════════════════════════


class TestDataIntegrity:
    """Vérifie que les fichiers de données existent et sont non vides."""

    def test_all_rule_files_exist(self) -> None:
        for rule in BUILTIN_RULES:
            path = RULES_DIR / str(rule["filename"])
            assert path.exists(), f"Fichier manquant : {path}"
            assert path.stat().st_size > 0, f"Fichier vide : {path}"

    def test_all_wordlist_files_exist(self) -> None:
        for wl in BUILTIN_WORDLISTS:
            path = WORDLISTS_DIR / str(wl["filename"])
            assert path.exists(), f"Fichier manquant : {path}"
            assert path.stat().st_size > 0, f"Fichier vide : {path}"

    def test_all_mask_files_exist(self) -> None:
        for mask in BUILTIN_MASKS:
            path = MASKS_DIR / str(mask["filename"])
            assert path.exists(), f"Fichier manquant : {path}"
            assert path.stat().st_size > 0, f"Fichier vide : {path}"

    def test_files_under_100kb(self) -> None:
        """Contrainte : pas de fichier > 100 Ko."""
        max_size = 100 * 1024
        for rule in BUILTIN_RULES:
            path = RULES_DIR / str(rule["filename"])
            if path.exists():
                assert path.stat().st_size <= max_size, (
                    f"{path.name} dépasse 100 Ko ({path.stat().st_size} octets). "
                    "Déplacer vers téléchargement externe."
                )
        for wl in BUILTIN_WORDLISTS:
            path = WORDLISTS_DIR / str(wl["filename"])
            if path.exists():
                assert path.stat().st_size <= max_size, (
                    f"{path.name} dépasse 100 Ko ({path.stat().st_size} octets)."
                )
        for mask in BUILTIN_MASKS:
            path = MASKS_DIR / str(mask["filename"])
            if path.exists():
                assert path.stat().st_size <= max_size, (
                    f"{path.name} dépasse 100 Ko ({path.stat().st_size} octets)."
                )

    def test_wordlist_line_count(self) -> None:
        """Vérifie le nombre approximatif de lignes."""
        for wl in BUILTIN_WORDLISTS:
            path = WORDLISTS_DIR / str(wl["filename"])
            if path.exists():
                lines = path.read_text(encoding="utf-8").splitlines()
                # Filtrer les lignes vides et les commentaires
                valid = [l for l in lines if l.strip() and not l.strip().startswith("#")]
                expected = int(wl.get("word_count", 0))
                if expected > 0:
                    assert abs(len(valid) - expected) / max(expected, 1) < 0.15, (
                        f"{wl['name']}: attendu ~{expected} lignes, trouvé {len(valid)}"
                    )


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Summary
# ══════════════════════════════════════════════════════════════════════════════


class TestSummary:
    """Tests de summary()."""

    def test_summary_has_all_keys(self, lib: CrackingLibrary) -> None:
        s = lib.summary()
        for key in ("wordlists", "rules", "masks"):
            assert key in s
            assert "total" in s[key]
            assert "installed" in s[key]
            assert "items" in s[key]

    def test_summary_counts_match(self, lib: CrackingLibrary) -> None:
        s = lib.summary()
        assert s["wordlists"]["total"] == len(lib.list_wordlists())
        assert s["rules"]["total"] == len(lib.list_rules())
        assert s["masks"]["total"] == len(lib.list_masks())

    def test_summary_installed_all_builtin(self, lib: CrackingLibrary) -> None:
        s = lib.summary()
        assert s["rules"]["installed"] == len(BUILTIN_RULES)
        assert s["wordlists"]["installed"] >= len(BUILTIN_WORDLISTS)
        assert s["masks"]["installed"] == len(BUILTIN_MASKS)


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Modèles Pydantic
# ══════════════════════════════════════════════════════════════════════════════


class TestPydanticModels:
    """Tests des modèles Pydantic."""

    def test_wordlist_info_defaults(self) -> None:
        wl = WordlistInfo(name="test", filename="test.txt", path="/tmp/test.txt", description="Test")
        assert wl.word_count == 0
        assert wl.size_bytes == 0
        assert wl.exists is False
        assert wl.installed is True

    def test_wordlist_info_full(self) -> None:
        wl = WordlistInfo(
            name="test",
            filename="test.txt",
            path="/tmp/test.txt",
            description="Test wordlist",
            word_count=1000,
            size_bytes=4096,
            exists=True,
            installed=True,
        )
        assert wl.word_count == 1000
        assert wl.size_bytes == 4096

    def test_rule_info_defaults(self) -> None:
        rule = RuleInfo(
            name="test",
            filename="test.rule",
            path="/tmp/test.rule",
            description="Test rule",
        )
        assert rule.rule_count == 0
        assert rule.size_bytes == 0
        assert rule.exists is False
        assert rule.installed is True
        assert rule.external_url is None

    def test_rule_info_with_external(self) -> None:
        rule = RuleInfo(
            name="test",
            filename="test.rule",
            path="/tmp/test.rule",
            description="Test",
            external_url="https://example.com/test.rule",
        )
        assert rule.external_url == "https://example.com/test.rule"

    def test_mask_info_defaults(self) -> None:
        mask = MaskInfo(
            name="test",
            filename="test.hcmask",
            path="/tmp/test.hcmask",
            description="Test mask",
        )
        assert mask.mask_count == 0
        assert mask.size_bytes == 0
        assert mask.exists is False

    def test_mask_info_full(self) -> None:
        mask = MaskInfo(
            name="test",
            filename="test.hcmask",
            path="/tmp/test.hcmask",
            description="Test mask",
            mask_count=50,
            size_bytes=2048,
            exists=True,
        )
        assert mask.mask_count == 50
        assert mask.exists is True

    def test_model_dumps(self) -> None:
        """Vérifie que les modèles peuvent être sérialisés."""
        wl = WordlistInfo(name="test", filename="t.txt", path="/t.txt", description="Test")
        data = wl.model_dump()
        assert data["name"] == "test"
        assert isinstance(data, dict)


# ══════════════════════════════════════════════════════════════════════════════
# Tests — Gestion rockyou (absence)
# ══════════════════════════════════════════════════════════════════════════════


class TestRockyou:
    """Tests du comportement rockyou (graceful degradation)."""

    def test_get_rockyou_raises_if_not_found(self, lib: CrackingLibrary) -> None:
        """Le gestionnaire doit marcher même si rockyou n'est pas installé."""
        with pytest.raises(FileNotFoundError) as excinfo:
            lib.get_wordlist_path("rockyou")
        assert "n'est pas installé" in str(excinfo.value) or "introuvable" in str(excinfo.value)

    def test_wordlists_still_work_without_rockyou(self, lib: CrackingLibrary) -> None:
        """Les wordlists built-in fonctionnent sans rockyou."""
        wordlists = lib.list_wordlists()
        assert any(w.name == "common-1000" for w in wordlists)
        path = lib.get_wordlist_path("common-1000")
        assert path.exists()

    def test_verify_file_hash(self, tmp_path: Path, lib: CrackingLibrary) -> None:
        """Test de vérification de hash."""
        test_file = tmp_path / "test.txt"
        # Utiliser write_bytes pour éviter la conversion \n → \r\n sur Windows
        test_file.write_bytes(b"hello world\n")

        # SHA256 de "hello world\n"
        import hashlib

        expected = hashlib.sha256(b"hello world\n").hexdigest()
        assert lib.verify_file_hash(test_file, expected, "sha256")

        # Mauvais hash
        assert not lib.verify_file_hash(test_file, "0" * 64, "sha256")
