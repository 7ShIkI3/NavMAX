"""Tests pour les wrappers AD — Certipy et Responder.

Teste les modèles de données, le parsing des sorties,
et la construction des commandes (sans exécuter les binaires réels).
"""

import json
import os
import tempfile
from pathlib import Path
from datetime import datetime

import pytest

from navmax.ad.certipy_wrapper import (
    CertipyCertInfo,
    CertipyFinding,
    CertipyWrapper,
)
from navmax.ad.responder_wrapper import (
    NTLMHash,
    ResponderMode,
    ResponderStatus,
    ResponderWrapper,
)


# ═══════════════════════════════════════════════════════════════
# Certipy Wrapper
# ═══════════════════════════════════════════════════════════════


class TestCertipyModels:
    """Tests des modèles de données certipy."""

    def test_certipy_finding_defaults(self) -> None:
        finding = CertipyFinding(
            vulnerability="ESC1",
            template="DomainController",
            ca="corp-DC-CA",
        )
        assert finding.vulnerability == "ESC1"
        assert finding.template == "DomainController"
        assert finding.ca == "corp-DC-CA"
        assert finding.description == ""

    def test_certipy_finding_full(self) -> None:
        finding = CertipyFinding(
            vulnerability="ESC1",
            template="DomainController",
            ca="corp-DC-CA",
            description="Enrollee supplies subject + Client Auth",
            command="certipy req -u user@corp.local -p '*' -ca 'corp-DC-CA' -template 'DomainController' -upn 'admin@corp.local'",
        )
        assert "certipy req" in finding.command
        assert "upn" in finding.command

    def test_certipy_cert_info_defaults(self) -> None:
        info = CertipyCertInfo()
        assert info.cert_file == ""
        assert info.key_file == ""
        assert info.pfx_file == ""
        assert info.template == ""

    def test_certipy_cert_info_full(self) -> None:
        info = CertipyCertInfo(
            cert_file="/tmp/cert.crt",
            key_file="/tmp/cert.key",
            pfx_file="/tmp/cert.pfx",
            template="DomainController",
            upn="admin@corp.local",
        )
        assert "cert.pfx" in info.pfx_file
        assert info.upn == "admin@corp.local"


class TestCertipyWrapper:
    """Tests du wrapper certipy (sans binaire réel)."""

    def test_available_property(self) -> None:
        """Vérifie que available retourne False sans certipy."""
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        assert wrapper.available is False

    def test_check_installation(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        msg = wrapper.check_installation()
        assert "n'est pas installé" in msg
        assert "certipy-ad" in msg

    def test_classify_esc1(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        assert wrapper._classify_vulnerability("Enrollee supplies subject") == "ESC1"
        assert wrapper._classify_vulnerability("Client Authentication") == "ESC1"

    def test_classify_esc2(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        assert wrapper._classify_vulnerability("Any Purpose") == "ESC2"

    def test_classify_esc3(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        assert wrapper._classify_vulnerability("Enrollment Agent") == "ESC3"
        assert wrapper._classify_vulnerability("Certificate Request Agent") == "ESC3"

    def test_classify_esc4(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        assert wrapper._classify_vulnerability("Weak ACL on template") == "ESC4"
        assert wrapper._classify_vulnerability("Write permission") == "ESC4"

    def test_classify_unknown(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        assert wrapper._classify_vulnerability("Unknown vulnerability") == ""

    def test_build_exploit_command_esc1(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        cmd = wrapper._build_exploit_command("ESC1", "DomainController", "corp-DC-CA")
        assert "certipy req" in cmd
        assert "-upn" in cmd
        assert "DomainController" in cmd

    def test_build_exploit_command_esc6(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        cmd = wrapper._build_exploit_command("ESC6", "UserTemplate", "corp-CA")
        assert "certipy req" in cmd

    def test_build_exploit_command_unknown(self) -> None:
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        cmd = wrapper._build_exploit_command("UNKNOWN", "Template", "CA")
        assert cmd == "Voir documentation certipy"


class TestCertipyFindParsing:
    """Teste le parsing de la sortie certipy find."""

    def test_parse_certipy_find_output(self, tmp_path: Path) -> None:
        """Parse un fichier JSON simulé de certipy find."""
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")

        mock_data = {
            "Certificate Authorities": [
                {
                    "CA Name": "corp-DC-CA",
                    "Templates": [
                        {
                            "Template Name": "DomainController",
                            "Vulnerabilities": [
                                "Enrollee supplies subject",
                                "Client Authentication",
                            ],
                        },
                        {
                            "Template Name": "User",
                            "Vulnerabilities": [
                                "Any Purpose",
                            ],
                        },
                    ],
                },
            ],
        }

        json_file = tmp_path / "corp.local.json"
        json_file.write_text(json.dumps(mock_data))

        findings = wrapper._parse_certipy_find_output(str(tmp_path))

        assert len(findings) == 3  # 2 vulns for DomainController + 1 for User
        esc1_findings = [f for f in findings if f.vulnerability == "ESC1"]
        assert len(esc1_findings) >= 1
        assert esc1_findings[0].template == "DomainController"
        assert esc1_findings[0].ca == "corp-DC-CA"

        esc2_findings = [f for f in findings if f.vulnerability == "ESC2"]
        assert len(esc2_findings) >= 1
        assert esc2_findings[0].template == "User"

    def test_parse_empty_output(self, tmp_path: Path) -> None:
        """Parse un fichier JSON vide."""
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")

        mock_data = {"Certificate Authorities": []}
        json_file = tmp_path / "empty.json"
        json_file.write_text(json.dumps(mock_data))

        findings = wrapper._parse_certipy_find_output(str(tmp_path))
        assert len(findings) == 0

    def test_find_no_json_files(self, tmp_path: Path) -> None:
        """Aucun fichier JSON dans le répertoire."""
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        findings = wrapper._parse_certipy_find_output(str(tmp_path))
        assert len(findings) == 0

    def test_find_cert_files(self, tmp_path: Path) -> None:
        """Teste la détection des fichiers de certificat."""
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")

        # Créer des fichiers simulés
        (tmp_path / "cert_admin.pfx").write_text("fake pfx")
        (tmp_path / "cert_admin.crt").write_text("fake crt")
        (tmp_path / "cert_admin.key").write_text("fake key")

        info = wrapper._find_cert_files(str(tmp_path), "DomainController")
        assert info is not None
        assert info.pfx_file.endswith(".pfx")
        assert info.cert_file.endswith(".crt")
        assert info.key_file.endswith(".key")
        assert info.template == "DomainController"

    def test_find_no_cert_files(self, tmp_path: Path) -> None:
        """Aucun fichier de certificat."""
        wrapper = CertipyWrapper(certipy_path="/nonexistent/certipy")
        info = wrapper._find_cert_files(str(tmp_path), "Template")
        assert info is None

    def test_cleanup_dir(self) -> None:
        """Teste le nettoyage de répertoire."""
        d = tempfile.mkdtemp()
        p = Path(d) / "test.txt"
        p.write_text("test")
        CertipyWrapper._cleanup_dir(d)
        assert not os.path.isdir(d)


# ═══════════════════════════════════════════════════════════════
# Responder Wrapper
# ═══════════════════════════════════════════════════════════════


class TestResponderModels:
    """Tests des modèles de données Responder."""

    def test_ntlm_hash_defaults(self) -> None:
        h = NTLMHash()
        assert h.hash_type == ""
        assert h.username == ""
        assert h.hash_value == ""

    def test_ntlm_hash_full(self) -> None:
        h = NTLMHash(
            hash_type="NTLMv2",
            username="admin",
            domain="CORP",
            hash_value="admin::CORP:1122334455667788:hashvalue:challengehash",
            challenge="1122334455667788",
        )
        assert h.hash_type == "NTLMv2"
        assert h.username == "admin"
        assert "1122334455667788" in h.hash_value

    def test_responder_status_defaults(self) -> None:
        s = ResponderStatus()
        assert s.running is False
        assert s.pid is None
        assert s.hashes_captured == 0

    def test_responder_status_running(self) -> None:
        s = ResponderStatus(
            running=True,
            pid=12345,
            interface="eth0",
            hashes_captured=5,
            uptime_seconds=120.0,
        )
        assert s.running is True
        assert s.pid == 12345
        assert s.hashes_captured == 5

    def test_responder_mode_values(self) -> None:
        assert ResponderMode.ALL.value == "ALL"
        assert ResponderMode.SMB.value == "SMB"
        assert ResponderMode.HTTP.value == "HTTP"
        assert ResponderMode.LDAP.value == "LDAP"


class TestResponderWrapper:
    """Tests du wrapper Responder (sans binaire réel)."""

    def test_available_property(self) -> None:
        """Vérifie que available retourne False sans Responder."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        assert wrapper.available is False

    def test_check_installation(self) -> None:
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        msg = wrapper.check_installation()
        assert "n'est pas installé" in msg

    def test_status_when_not_running(self) -> None:
        """Status retourne running=False quand pas lancé."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        s = wrapper.status()
        assert s.running is False
        assert s.hashes_captured == 0

    def test_start_fails_without_binary(self) -> None:
        """Vérifie que start retourne une erreur sans Responder."""
        import asyncio

        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        status = asyncio.run(wrapper.start(interface="eth0"))
        assert status.error is not None
        assert "n'est pas installé" in status.error


class TestResponderSessionParsing:
    """Teste le parsing du fichier Responder-Session.log."""

    def test_parse_ntlmv2_hash(self) -> None:
        """Parse un hash NTLMv2 standard."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        line = (
            "admin::CORP:1122334455667788:"
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:"
            "aabbccddee0011223344556677889900"
        )
        h = wrapper._parse_hash_line(line)
        assert h is not None
        assert h.hash_type == "NTLMv2"
        assert h.username == "admin"
        assert h.domain == "CORP"
        assert h.challenge == "1122334455667788"

    def test_parse_ntlmv2_with_backslash(self) -> None:
        """Parse un hash NTLMv2 avec préfixe DOMAIN\\username."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        line = (
            "CORP\\admin::CORP:1122334455667788:"
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:"
            "aabbccddee0011223344556677889900"
        )
        h = wrapper._parse_hash_line(line)
        assert h is not None
        assert h.username == "admin"
        assert h.domain == "CORP"

    def test_parse_invalid_line(self) -> None:
        """Les lignes invalides retournent None."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        assert wrapper._parse_hash_line("") is None
        assert wrapper._parse_hash_line("not a hash") is None
        assert wrapper._parse_hash_line("# comment") is None

    def test_parse_empty_line(self) -> None:
        """Les lignes vides retournent None."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        assert wrapper._parse_hash_line("") is None
        assert wrapper._parse_hash_line("   ") is None

    def test_full_session_file_parsing(self, tmp_path: Path) -> None:
        """Parse un fichier de session complet."""
        wrapper = ResponderWrapper(responder_path="/nonexistent/Responder")
        wrapper._session_file = str(tmp_path / "Responder-Session.log")

        session_content = """[HTTP] NTLMv2 captured for CORP\\admin
admin::CORP:1122334455667788:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:aabbccddee0011223344556677889900

[SMB] NTLMv2 captured for CORP\\svc_user
svc_user::CORP:ffeeddccbbaa9988:1234567890abcdef1234567890abcdef:00112233445566778899aabbccddeeff

# Comment line
some invalid line
"""
        Path(wrapper._session_file).write_text(session_content)

        hashes = wrapper._parse_session_file()
        assert len(hashes) == 2
        assert hashes[0].username == "admin"
        assert hashes[0].domain == "CORP"
        assert hashes[1].username == "svc_user"


class TestResponderHashcatJtr:
    """Tests de conversion en formats hashcat / JtR."""

    def test_make_hashcat_format(self) -> None:
        hashes = [
            NTLMHash(
                hash_type="NTLMv2",
                username="admin",
                domain="CORP",
                hash_value="admin::CORP:1122334455667788:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:aabbccddee0011223344556677889900",
            ),
        ]
        result = ResponderWrapper.make_hashcat_format(hashes)
        assert "admin::CORP" in result
        assert "1122334455667788" in result

    def test_make_hashcat_empty(self) -> None:
        result = ResponderWrapper.make_hashcat_format([])
        assert result == ""

    def test_find_session_file_default(self) -> None:
        path = ResponderWrapper._find_session_file("/tmp")
        assert path is not None
        assert "Responder-Session.log" in path
