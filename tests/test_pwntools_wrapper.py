"""Tests du wrapper pwntools — PwntoolsWrapper.

Tous les tests sont mockés : aucune dépendance réelle à pwntools n'est
nécessaire. Les fonctionnalités de fallback (pattern_create, pattern_offset)
sont testées directement.

Tests:
    - TestPwntoolsModels: Modèles Pydantic (ShellcodeSpec, RopGadget, ExploitResult)
    - TestPwntoolsWrapperInstallation: check_installation, available, version
    - TestPwntoolsWrapperShellcode: generate_shellcode (mocké)
    - TestPwntoolsWrapperPattern: pattern_create / pattern_offset (fallback)
    - TestPwntoolsWrapperAsmDisasm: asm / disasm (mock + fallback)
    - TestPwntoolsWrapperNetwork: connect_remote / connect_ssh (mocké)
    - TestPwntoolsWrapperRop: find_rop_gadgets (mocké)
"""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from navmax.exploit.pwntools_wrapper import (
    ExploitResult,
    PwntoolsWrapper,
    RopGadget,
    ShellcodeSpec,
    pwntools,
)


# ═══════════════════════════════════════════════════════════════════
# Modèles Pydantic
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsModels:
    """Tests des modèles de données (ShellcodeSpec, RopGadget, ExploitResult)."""

    def test_shellcode_spec_defaults(self) -> None:
        """Vérifie les valeurs par défaut de ShellcodeSpec."""
        spec = ShellcodeSpec()
        assert spec.arch == "x86_64"
        assert spec.os == "linux"
        assert spec.payload == "exec"
        assert spec.raw == b""
        assert spec.hex == ""
        assert spec.length == 0
        assert spec.assembly == ""

    def test_shellcode_spec_with_data(self) -> None:
        """Vérifie la construction avec données."""
        raw = b"\x90\x90\xcc"
        spec = ShellcodeSpec(
            arch="i386",
            os="linux",
            payload="bind_shell",
            raw=raw,
            hex=raw.hex(),
            length=len(raw),
            assembly="nop\\nnop\\nint3",
        )
        assert spec.arch == "i386"
        assert spec.os == "linux"
        assert spec.payload == "bind_shell"
        assert spec.raw == b"\x90\x90\xcc"
        assert spec.hex == "9090cc"
        assert spec.length == 3
        assert spec.assembly == "nop\\nnop\\nint3"
        assert spec.error is None

    def test_shellcode_spec_with_error(self) -> None:
        """Vérifie ShellcodeSpec avec une erreur."""
        spec = ShellcodeSpec(error="pwntools non disponible")
        assert spec.error == "pwntools non disponible"
        assert spec.raw == b""

    def test_rop_gadget_defaults(self) -> None:
        """Vérifie les valeurs par défaut de RopGadget."""
        g = RopGadget(address=0x401234, instructions="pop rdi; ret")
        assert g.address == 0x401234
        assert g.instructions == "pop rdi; ret"
        assert g.raw is None

    def test_rop_gadget_with_raw(self) -> None:
        """Vérifie RopGadget avec bytes bruts."""
        raw = b"\x5f\xc3"
        g = RopGadget(address=0x401000, instructions="pop rdi; ret", raw=raw)
        assert g.raw == b"\x5f\xc3"

    def test_exploit_result_defaults(self) -> None:
        """Vérifie les valeurs par défaut de ExploitResult."""
        r = ExploitResult()
        assert r.success is False
        assert r.technique == ""
        assert r.target == ""
        assert r.address is None
        assert r.overflow_offset is None
        assert r.shellcode is None
        assert r.output == ""
        assert r.error is None
        assert r.details == {}

    def test_exploit_result_success(self) -> None:
        """Vérifie ExploitResult en mode succès."""
        r = ExploitResult(
            success=True,
            technique="format_string",
            target="system",
            address=0x7ffff7a52390,
            overflow_offset=40,
            shellcode=b"\x90",
            output="Payload généré",
            details={"payload_size": 128},
        )
        assert r.success is True
        assert r.technique == "format_string"
        assert r.address == 0x7FFFF7A52390
        assert r.overflow_offset == 40
        assert r.shellcode == b"\x90"
        assert r.details["payload_size"] == 128


# ═══════════════════════════════════════════════════════════════════
# Installation
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperInstallation:
    """Tests de détection d'installation de pwntools."""

    def test_check_installation_sans_pwntools(self) -> None:
        """check_installation retourne False sans pwntools."""
        wrapper = PwntoolsWrapper()
        # On force _check_import à échouer
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            assert wrapper.check_installation() is False

    def test_check_installation_avec_pwntools(self) -> None:
        """check_installation retourne True avec pwntools mocké."""
        wrapper = PwntoolsWrapper()
        wrapper._pwntools = MagicMock()
        wrapper._available = True
        wrapper._version = "4.12.0"
        assert wrapper.check_installation() is True

    def test_available_property(self) -> None:
        """available retourne False par défaut (sans pwntools)."""
        wrapper = PwntoolsWrapper()
        # Simuler l'absence de pwntools
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            assert wrapper.available is False

    def test_version_property_vide_sans_pwntools(self) -> None:
        """version est vide quand pwntools n'est pas installé."""
        wrapper = PwntoolsWrapper()
        assert wrapper.version == ""

    def test_install_instructions(self) -> None:
        """install_instructions retourne des instructions valides."""
        instructions = PwntoolsWrapper.install_instructions()
        assert "pip install pwntools" in instructions
        assert "from pwn import" in instructions

    def test_singleton_disponible(self) -> None:
        """Le singleton 'pwntools' est une instance de PwntoolsWrapper."""
        assert isinstance(pwntools, PwntoolsWrapper)


# ═══════════════════════════════════════════════════════════════════
# Shellcode
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperShellcode:
    """Tests de génération de shellcode (mockée)."""

    def test_generate_shellcode_sans_pwntools(self) -> None:
        """generate_shellcode retourne un spec vide sans pwntools."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            spec = wrapper.generate_shellcode("x86_64", "linux", "exec")
        assert isinstance(spec, ShellcodeSpec)
        assert spec.arch == "x86_64"
        assert spec.os == "linux"
        assert spec.payload == "exec"
        assert spec.raw == b""

    def test_generate_shellcode_avec_pwntools(self) -> None:
        """generate_shellcode délègue à pwntools.shellcraft."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()

        # Configurer le mock shellcraft
        mock_shellcode = b"\x31\xc0\x48\xbb\x2f\x62\x69\x6e"
        wrapper._pwntools.shellcraft.linux.exec.return_value = mock_shellcode

        spec = wrapper.generate_shellcode("x86_64", "linux", "exec")

        assert spec.raw == mock_shellcode
        assert spec.hex == mock_shellcode.hex()
        assert spec.length == len(mock_shellcode)
        wrapper._pwntools.shellcraft.linux.exec.assert_called_once_with(
            arch="x86_64"
        )

    def test_generate_shellcode_payload_inconnu(self) -> None:
        """generate_shellcode gère les payloads inconnus."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()

        # Payload inexistant
        del wrapper._pwntools.shellcraft.linux.invalid_payload

        spec = wrapper.generate_shellcode("x86_64", "linux", "invalid_payload")

        assert spec.raw == b""
        assert spec.length == 0

    def test_generate_shellcode_avec_kwargs(self) -> None:
        """generate_shellcode transmet les **kwargs au générateur."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        wrapper._pwntools.shellcraft.linux.sh.return_value = b"\xeb\x1f"

        spec = wrapper.generate_shellcode(
            "x86_64", "linux", "sh", host="10.0.0.1", port=4444
        )

        assert spec.raw == b"\xeb\x1f"
        wrapper._pwntools.shellcraft.linux.sh.assert_called_once_with(
            arch="x86_64", host="10.0.0.1", port=4444
        )


# ═══════════════════════════════════════════════════════════════════
# Pattern / Buffer Overflow
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperPattern:
    """Tests de pattern_create et pattern_offset (fallback intégré)."""

    def test_pattern_create_default_length(self) -> None:
        """pattern_create avec longueur par défaut (100)."""
        pat = PwntoolsWrapper.pattern_create()
        assert isinstance(pat, bytes)
        assert len(pat) == 100

    def test_pattern_create_custom_length(self) -> None:
        """pattern_create avec longueur personnalisée."""
        pat = PwntoolsWrapper.pattern_create(256)
        assert len(pat) == 256

    def test_pattern_create_zero_length(self) -> None:
        """pattern_create avec longueur 0."""
        pat = PwntoolsWrapper.pattern_create(0)
        assert len(pat) == 0

    def test_pattern_create_uniqueness(self) -> None:
        """Le motif produit des séquences de 4 octets uniques."""
        pat = PwntoolsWrapper.pattern_create(500)
        # Vérifier que les premiers 4-octets sont distincts
        seen: set[bytes] = set()
        for i in range(0, min(200, len(pat) - 4), 4):
            chunk = pat[i : i + 4]
            assert chunk not in seen, f"Duplication à l'offset {i}: {chunk!r}"
            seen.add(chunk)

    def test_pattern_offset_32bit(self) -> None:
        """pattern_offset trouve une adresse 32-bit."""
        pat = PwntoolsWrapper.pattern_create(200)
        # Trouver l'offset d'une adresse au début du motif
        addr_bytes = pat[0:4]
        addr = struct.unpack("<I", addr_bytes)[0]
        offset = PwntoolsWrapper.pattern_offset(pat, addr)
        assert offset == 0

    def test_pattern_offset_64bit(self) -> None:
        """pattern_offset trouve une adresse 64-bit."""
        pat = PwntoolsWrapper.pattern_create(200)
        addr_bytes = pat[0:8]
        addr = struct.unpack("<Q", addr_bytes)[0]
        offset = PwntoolsWrapper.pattern_offset(pat, addr)
        assert offset == 0

    def test_pattern_offset_bytes(self) -> None:
        """pattern_offset fonctionne avec des bytes bruts."""
        pat = PwntoolsWrapper.pattern_create(100)
        chunk = pat[12:16]
        offset = PwntoolsWrapper.pattern_offset(pat, chunk)
        assert offset == 12

    def test_pattern_offset_string(self) -> None:
        """pattern_offset fonctionne avec une chaîne."""
        pat = PwntoolsWrapper.pattern_create(100)
        chunk = pat[24:28]
        offset = PwntoolsWrapper.pattern_offset(pat, chunk.decode("latin-1"))
        assert offset == 24

    def test_pattern_offset_not_found(self) -> None:
        """pattern_offset retourne -1 si la valeur n'est pas dans le motif."""
        pat = PwntoolsWrapper.pattern_create(50)
        offset = PwntoolsWrapper.pattern_offset(pat, 0xDEADBEEF)
        assert offset == -1

    def test_pattern_offset_not_found_bytes(self) -> None:
        """pattern_offset retourne -1 pour des bytes absents."""
        pat = PwntoolsWrapper.pattern_create(50)
        offset = PwntoolsWrapper.pattern_offset(pat, b"\xff\xff\xff\xff")
        assert offset == -1


# ═══════════════════════════════════════════════════════════════════
# Assembleur / Désassembleur
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperAsmDisasm:
    """Tests de l'assembleur et désassembleur."""

    def test_asm_sans_pwntools_fallback_nop(self) -> None:
        """asm utilise le fallback sans pwntools pour NOP."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            result = wrapper.asm("nop")
        assert result == b"\x90"

    def test_asm_sans_pwntools_fallback_ret(self) -> None:
        """asm fallback pour RET."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            result = wrapper.asm("ret")
        assert result == b"\xc3"

    def test_asm_sans_pwntools_fallback_inconnu(self) -> None:
        """asm fallback retourne bytes vide pour instruction inconnue."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            result = wrapper.asm("invalid_instruction_xyz")
        assert result == b""

    def test_disasm_sans_pwntools(self) -> None:
        """disasm retourne hex sans pwntools."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            result = wrapper.disasm(b"\x90\x90")
        assert result == "90 90"

    def test_asm_avec_pwntools(self) -> None:
        """asm délègue à pwntools.asm."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        wrapper._pwntools.asm.return_value = b"\x90"

        result = wrapper.asm("nop", arch="x86_64")

        assert result == b"\x90"
        wrapper._pwntools.asm.assert_called_once_with("nop", arch="x86_64")

    def test_disasm_avec_pwntools(self) -> None:
        """disasm délègue à pwntools.disasm."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        wrapper._pwntools.disasm.return_value = "   0:   90                      nop"

        result = wrapper.disasm(b"\x90", arch="x86_64")

        assert "nop" in result
        wrapper._pwntools.disasm.assert_called_once_with(b"\x90", arch="x86_64")


# ═══════════════════════════════════════════════════════════════════
# Réseau (Tubes)
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperNetwork:
    """Tests de connexion réseau (remote, SSH)."""

    def test_connect_remote_sans_pwntools(self) -> None:
        """connect_remote retourne None sans pwntools."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            tube = wrapper.connect_remote("10.0.0.1", 4444)
        assert tube is None

    def test_connect_remote_avec_pwntools(self) -> None:
        """connect_remote délègue à pwntools.remote."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_tube = MagicMock()
        wrapper._pwntools.remote.return_value = mock_tube

        tube = wrapper.connect_remote("10.0.0.1", 4444, timeout=5)

        assert tube is mock_tube
        wrapper._pwntools.remote.assert_called_once_with(
            "10.0.0.1", 4444, timeout=5
        )

    def test_connect_remote_ssl(self) -> None:
        """connect_remote avec protocol='ssl' utilise pwntools.ssl."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_tube = MagicMock()
        wrapper._pwntools.ssl.return_value = mock_tube

        tube = wrapper.connect_remote("10.0.0.1", 443, protocol="ssl")

        assert tube is mock_tube
        wrapper._pwntools.ssl.assert_called_once_with("10.0.0.1", 443, timeout=None)

    def test_connect_ssh_sans_pwntools(self) -> None:
        """connect_ssh retourne None sans pwntools."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            ssh = wrapper.connect_ssh("10.0.0.1", "root", password="toor")
        assert ssh is None

    def test_connect_ssh_avec_pwntools(self) -> None:
        """connect_ssh délègue à pwntools.ssh."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_ssh = MagicMock()
        wrapper._pwntools.ssh.return_value = mock_ssh

        ssh = wrapper.connect_ssh(
            "10.0.0.1", "root", password="toor", port=2222
        )

        assert ssh is mock_ssh
        wrapper._pwntools.ssh.assert_called_once_with(
            "10.0.0.1", user="root", password="toor", port=2222, keyfile=None
        )

    def test_connect_ssh_avec_clef(self) -> None:
        """connect_ssh avec key_file."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_ssh = MagicMock()
        wrapper._pwntools.ssh.return_value = mock_ssh

        ssh = wrapper.connect_ssh(
            "10.0.0.1", "root", key_file="/home/user/.ssh/id_rsa"
        )

        assert ssh is mock_ssh
        wrapper._pwntools.ssh.assert_called_once_with(
            "10.0.0.1",
            user="root",
            password=None,
            port=22,
            keyfile="/home/user/.ssh/id_rsa",
        )


# ═══════════════════════════════════════════════════════════════════
# ROP Gadgets
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperRop:
    """Tests de recherche de gadgets ROP (mockés)."""

    def test_find_rop_gadgets_sans_pwntools(self) -> None:
        """find_rop_gadgets retourne liste vide sans pwntools."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            gadgets = wrapper.find_rop_gadgets("/bin/ls")
        assert gadgets == []

    def test_find_rop_gadgets_binaire_introuvable(self) -> None:
        """find_rop_gadgets retourne liste vide si le binaire n'existe pas."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        gadgets = wrapper.find_rop_gadgets("/chemin/invalide/binaire")
        assert gadgets == []

    def test_find_rop_gadgets_avec_resultats(self, tmp_path: Path) -> None:
        """find_rop_gadgets retourne les gadgets trouvés."""
        binary = tmp_path / "test_binary"
        binary.write_bytes(b"\x7fELF...")  # Faux ELF

        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()

        # Simuler pwntools.ELF et pwntools.ROP
        mock_elf = MagicMock()
        mock_rop = MagicMock()
        mock_rop.gadgets = {
            0x401000: "pop rdi; ret",
            0x401002: "pop rsi; ret",
            0x401004: "pop rdx; ret",
            0x401006: "syscall; ret",
        }

        wrapper._pwntools.ELF.return_value = mock_elf
        wrapper._pwntools.ROP.return_value = mock_rop

        gadgets = wrapper.find_rop_gadgets(str(binary))

        assert len(gadgets) == 4
        assert all(isinstance(g, RopGadget) for g in gadgets)
        assert gadgets[0].address == 0x401000
        assert gadgets[0].instructions == "pop rdi; ret"
        assert gadgets[3].instructions == "syscall; ret"

    def test_find_rop_gadgets_avec_filtre(self, tmp_path: Path) -> None:
        """find_rop_gadgets filtre par chaîne de recherche."""
        binary = tmp_path / "test_binary2"
        binary.write_bytes(b"\x7fELF...")

        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_elf = MagicMock()
        mock_rop = MagicMock()
        mock_rop.gadgets = {
            0x401000: "pop rdi; ret",
            0x401002: "pop rsi; ret",
            0x401004: "pop rdx; ret",
            0x401006: "xor rax, rax; ret",
        }
        wrapper._pwntools.ELF.return_value = mock_elf
        wrapper._pwntools.ROP.return_value = mock_rop

        gadgets = wrapper.find_rop_gadgets(str(binary), search="pop rdi")

        assert len(gadgets) == 1
        assert gadgets[0].instructions == "pop rdi; ret"

    def test_find_rop_gadgets_avec_depth(self, tmp_path: Path) -> None:
        """find_rop_gadgets respecte le paramètre depth."""
        binary = tmp_path / "test_binary3"
        binary.write_bytes(b"\x7fELF...")

        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_elf = MagicMock()
        mock_rop = MagicMock()
        mock_rop.gadgets = {
            0x401000: "pop rdi; ret",
            0x401002: "pop rdi; pop rsi; ret",
            0x401004: "pop rdi; pop rsi; pop rdx; ret",
        }
        wrapper._pwntools.ELF.return_value = mock_elf
        wrapper._pwntools.ROP.return_value = mock_rop

        gadgets = wrapper.find_rop_gadgets(str(binary), depth=2)

        assert len(gadgets) == 1
        assert gadgets[0].instructions == "pop rdi; ret"


# ═══════════════════════════════════════════════════════════════════
# Format String
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsWrapperFormatString:
    """Tests d'exploitation format string (mockés)."""

    def test_exploit_format_string_sans_pwntools(self) -> None:
        """exploit_format_string retourne erreur sans pwntools."""
        wrapper = PwntoolsWrapper()
        with patch.object(wrapper, "_check_import") as mock:
            mock.side_effect = lambda: setattr(wrapper, "_available", False)
            result = wrapper.exploit_format_string("/bin/ls", "win")
        assert result.error == "pwntools n'est pas installé"
        assert result.success is False

    def test_exploit_format_string_binaire_introuvable(self) -> None:
        """exploit_format_string gère le binaire manquant."""
        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        result = wrapper.exploit_format_string("/inexistant", "win")
        assert "introuvable" in str(result.error)

    def test_exploit_format_string_cible_introuvable(self, tmp_path: Path) -> None:
        """exploit_format_string gère la fonction cible absente."""
        binary = tmp_path / "test_elf"
        binary.write_bytes(b"\x7fELF")

        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_elf = MagicMock()
        mock_elf.symbols = {}
        mock_elf.got = {}
        wrapper._pwntools.ELF.return_value = mock_elf
        wrapper._pwntools.ROP.return_value = MagicMock()

        result = wrapper.exploit_format_string(str(binary), "inexistant_func")
        assert "introuvable" in str(result.error)
        assert result.success is False

    def test_exploit_format_string_avec_offset(self, tmp_path: Path) -> None:
        """exploit_format_string construit un payload avec offset."""
        binary = tmp_path / "test_elf2"
        binary.write_bytes(b"\x7fELF")

        wrapper = PwntoolsWrapper()
        wrapper._available = True
        wrapper._pwntools = MagicMock()
        mock_elf = MagicMock()
        mock_elf.symbols = {"win": 0x401234}
        mock_elf.got = {}
        wrapper._pwntools.ELF.return_value = mock_elf
        wrapper._pwntools.ROP.return_value = MagicMock()
        wrapper._pwntools.fmtstr_payload = MagicMock(return_value=b"FAKEPAYLOAD")

        result = wrapper.exploit_format_string(str(binary), "win", offset=6)

        assert result.success is True
        assert result.address == 0x401234
        assert result.overflow_offset == 6
        assert result.technique == "format_string"
        wrapper._pwntools.fmtstr_payload.assert_called_once_with(6, {0x401234: 0x1})


# ═══════════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════════


class TestPwntoolsSingleton:
    """Tests du singleton pwntools (accès rapide)."""

    def test_singleton_est_instance(self) -> None:
        """pwntools est une instance de PwntoolsWrapper."""
        assert isinstance(pwntools, PwntoolsWrapper)

    def test_singleton_est_unique(self) -> None:
        """pwntools est le même objet que PwntoolsWrapper()."""
        from navmax.exploit.pwntools_wrapper import pwntools as p1

        assert p1 is pwntools
