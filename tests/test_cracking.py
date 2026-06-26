"""Tests pour le module cracking/ — hashcat, john, hydra wrappers.

Mock subprocess pour éviter de nécessiter les outils réels.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from navmax.cracking import (
    BaseCracker,
    CrackResult,
    CrackStatus,
    HashInfo,
    HashType,
    HashcatWrapper,
    HydraWrapper,
    JohnWrapper,
)
from navmax.cracking.base import HASHCAT_MODES, JOHN_FORMATS, detect_hash_type


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def dummy_hash_file(tmp_path: Path) -> Path:
    """Crée un faux fichier de hash NTLM."""
    f = tmp_path / "hashes.txt"
    f.write_text("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n")
    return f


@pytest.fixture
def dummy_wordlist(tmp_path: Path) -> Path:
    """Crée une fausse wordlist."""
    f = tmp_path / "wordlist.txt"
    f.write_text("password\n123456\nadmin\n")
    return f


@pytest.fixture
def dummy_bcrypt_hash(tmp_path: Path) -> Path:
    """Crée un faux fichier de hash bcrypt."""
    f = tmp_path / "bcrypt_hashes.txt"
    f.write_text("$2b$12$LJ3m4ys3Lk0TSwHmsY.Eae7eM5U5gk2HjG5g5kY3k9k8k7k6k5k4\n")
    return f


# ══════════════════════════════════════════════════════════════════════════════
# Tests BaseCracker
# ══════════════════════════════════════════════════════════════════════════════


class TestHashDetection:
    """Tests de détection de type de hash."""

    def test_detect_ntlm(self) -> None:
        info = detect_hash_type("Administrateur:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        assert info.hash_type == HashType.NTLM
        assert info.hashcat_mode == 1000
        assert info.format_john == "nt"

    def test_detect_ntlm_short_format(self) -> None:
        """Format NTLM simple (hash seul, mais avec LM:NT)."""
        info = detect_hash_type("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")
        assert info.hash_type == HashType.NTLM
        assert info.hashcat_mode == 1000

    def test_detect_md5(self) -> None:
        info = detect_hash_type("5d41402abc4b2a76b9719d911017c592")
        assert info.hash_type == HashType.MD5
        assert info.hashcat_mode == 0

    def test_detect_sha1(self) -> None:
        info = detect_hash_type("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")
        assert info.hash_type == HashType.SHA1
        assert info.hashcat_mode == 100

    def test_detect_sha256(self) -> None:
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        info = detect_hash_type(h)
        assert info.hash_type == HashType.SHA256
        assert info.hashcat_mode == 1400

    def test_detect_sha512(self) -> None:
        h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        info = detect_hash_type(h)
        assert info.hash_type == HashType.SHA512
        assert info.hashcat_mode == 1700

    def test_detect_bcrypt(self) -> None:
        info = detect_hash_type("$2b$12$LJ3m4ys3Lk0TSwHmsY.Eae7eM5U5gk2HjG5g5kY3k9k8k7k6k5k4")
        assert info.hash_type == HashType.BCRYPT
        assert info.hashcat_mode == 3200

    def test_detect_unknown(self) -> None:
        info = detect_hash_type("totoro")
        assert info.hash_type == HashType.UNKNOWN
        assert info.hashcat_mode == 0


class TestBaseCrackerInstallation:
    """Tests de vérification d'installation."""

    def test_available_when_binary_found(self) -> None:
        class TestCracker(BaseCracker):
            _binary_name = "test-bin"

            def get_version(self) -> str:
                return "1.0.0"

            async def crack(self, hash_file: str, wordlist: str, **options: dict) -> CrackResult:
                return CrackResult()

        cracker = TestCracker()
        with patch("shutil.which", return_value="/usr/bin/test-bin"):
            assert cracker.available is True

    def test_available_when_not_found(self) -> None:
        class TestCracker(BaseCracker):
            _binary_name = "nonexistent-bin"

            def get_version(self) -> str:
                return ""

            async def crack(self, hash_file: str, wordlist: str, **options: dict) -> CrackResult:
                return CrackResult()

        cracker = TestCracker()
        with patch("shutil.which", return_value=None):
            assert cracker.available is False

    def test_check_installation_message(self) -> None:
        class TestCracker(BaseCracker):
            _binary_name = "my-tool"

            def get_version(self) -> str:
                return "2.0.0"

            async def crack(self, hash_file: str, wordlist: str, **options: dict) -> CrackResult:
                return CrackResult()

        cracker = TestCracker()
        msg = cracker.check_installation()
        assert "n'est pas installé" in msg

        with patch("shutil.which", return_value="/usr/bin/my-tool"):
            msg2 = cracker.check_installation()
            assert "installé" in msg2
            assert "/usr/bin/my-tool" in msg2


# ══════════════════════════════════════════════════════════════════════════════
# Tests HashcatWrapper
# ══════════════════════════════════════════════════════════════════════════════


class TestHashcatWrapper:
    """Tests du wrapper hashcat."""

    def test_list_modes(self) -> None:
        hc = HashcatWrapper()
        modes = hc.list_modes()
        assert modes["ntlm"] == 1000
        assert modes["wpa2"] == 22000
        assert modes["bcrypt"] == 3200
        assert modes["md5"] == 0
        assert modes["sha256"] == 1400

    @pytest.mark.asyncio
    async def test_crack_not_available(self, dummy_hash_file: Path, dummy_wordlist: Path) -> None:
        """Test que crack retourne une erreur si hashcat n'est pas installé."""
        hc = HashcatWrapper()
        with patch.object(HashcatWrapper, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            result = await hc.crack(str(dummy_hash_file), str(dummy_wordlist))
            assert result.status == CrackStatus.ERROR
            assert "pas installé" in result.error

    @pytest.mark.asyncio
    async def test_crack_hash_file_not_found(self) -> None:
        """Test que crack retourne une erreur si le fichier de hash n'existe pas."""
        hc = HashcatWrapper()
        with patch.object(HashcatWrapper, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = True
            result = await hc.crack("/nonexistent/hashes.txt", "/nonexistent/wordlist.txt")
            assert result.status == CrackStatus.ERROR
            assert "introuvable" in result.error

    @pytest.mark.asyncio
    async def test_crack_wordlist_not_found(self, dummy_hash_file: Path) -> None:
        """Test que crack retourne une erreur si la wordlist n'existe pas."""
        hc = HashcatWrapper()
        with patch.object(HashcatWrapper, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = True
            result = await hc.crack(str(dummy_hash_file), "/nonexistent/wordlist.txt")
            assert result.status == CrackStatus.ERROR
            assert "Wordlist introuvable" in result.error

    @pytest.mark.asyncio
    async def test_crack_success(self, dummy_hash_file: Path, dummy_wordlist: Path) -> None:
        """Test un crack réussi avec subprocess mocké."""
        hc = HashcatWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"Session..........: hashcat\nStatus..........: Cracked\nHash.Target......: 31d6cfe0d16ae931b73c59d7e0c089c0\n"
                b"aad3b435b51404eeaad3b435b51404ee:password\n",
                b"",
            )
        )
        mock_proc.returncode = 0

        with (
            patch.object(HashcatWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await hc.crack(str(dummy_hash_file), str(dummy_wordlist))
            assert result.status == CrackStatus.SUCCESS
            assert result.cracked_password

    @pytest.mark.asyncio
    async def test_crack_timeout(self, dummy_hash_file: Path, dummy_wordlist: Path) -> None:
        """Test un timeout pendant le crack."""
        hc = HashcatWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch.object(HashcatWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await hc.crack(
                str(dummy_hash_file), str(dummy_wordlist), timeout=1,
            )
            assert result.status == CrackStatus.CANCELLED
            assert "Timeout" in result.error

    @pytest.mark.asyncio
    async def test_crack_failed(self, dummy_hash_file: Path, dummy_wordlist: Path) -> None:
        """Test un crack qui échoue (aucun hash chargé)."""
        hc = HashcatWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"Status.........: Exhausted\n", b"* Hashfile 'hashes.txt': No hashes loaded\n")
        )
        mock_proc.returncode = 1

        with (
            patch.object(HashcatWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await hc.crack(str(dummy_hash_file), str(dummy_wordlist))
            assert result.status == CrackStatus.FAILED
            assert result.error

    def test_parse_show_output(self) -> None:
        """Test du parsing de --show."""
        hc = HashcatWrapper()
        output = (
            "aad3b435b51404eeaad3b435b51404ee:password123\n"
            "31d6cfe0d16ae931b73c59d7e060c0:admin\n"
        )
        results = hc._parse_show_output(output)
        assert results["aad3b435b51404eeaad3b435b51404ee"] == "password123"
        assert results["31d6cfe0d16ae931b73c59d7e060c0"] == "admin"

    def test_build_args_default(self) -> None:
        """Test la construction des arguments par défaut."""
        hc = HashcatWrapper()
        with patch.object(HashcatWrapper, "available", new_callable=PropertyMock, return_value=True):
            args = hc._build_args("/tmp/hashes.txt", "/tmp/rockyou.txt", mode=1000)
            # Vérifier les éléments essentiels
            assert any("hashcat" in a or "/hashcat" in a for a in args)
            assert "-m" in args
            assert "1000" in args
            assert "-a0" in args
            assert "-O" in args  # optimized
            assert "-w" in args
            assert "3" in args
            assert "/tmp/hashes.txt" in args
            assert "/tmp/rockyou.txt" in args


# ══════════════════════════════════════════════════════════════════════════════
# Tests JohnWrapper
# ══════════════════════════════════════════════════════════════════════════════


class TestJohnWrapper:
    """Tests du wrapper John the Ripper."""

    def test_list_formats(self) -> None:
        john = JohnWrapper()
        formats = john.list_formats()
        assert formats["ntlm"] == "nt"
        assert formats["ssh"] == "ssh"
        assert formats["zip"] == "zip"
        assert formats["rar"] == "rar"
        assert formats["pdf"] == "pdf"
        assert formats["kerberos_tgt"] == "krb5tgs"

    @pytest.mark.asyncio
    async def test_crack_not_available(self) -> None:
        john = JohnWrapper()
        with patch.object(JohnWrapper, "available", new_callable=PropertyMock, return_value=False):
            result = await john.crack("hashes.txt", "wordlist.txt")
            assert result.status == CrackStatus.ERROR
            assert "pas installé" in result.error

    @pytest.mark.asyncio
    async def test_crack_hash_file_not_found(self) -> None:
        john = JohnWrapper()
        with patch.object(JohnWrapper, "available", new_callable=PropertyMock, return_value=True):
            result = await john.crack("/nonexistent/hashes.txt", "/nonexistent/wordlist.txt")
            assert result.status == CrackStatus.ERROR
            assert "introuvable" in result.error

    @pytest.mark.asyncio
    async def test_crack_success(self, dummy_hash_file: Path) -> None:
        """Test un crack john réussi avec subprocess mocké."""
        john = JohnWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"Loaded 1 password hash (NTLM)\n"
                b"Proceeding with wordlist\n"
                b"password          (Administrateur)\n"
                b"1g 0:00:00:01\n",
                b"",
            )
        )
        mock_proc.returncode = 0

        with (
            patch.object(JohnWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("os.path.isfile", return_value=True),
        ):
            result = await john.crack(str(dummy_hash_file), "wordlist.txt", fmt="nt")
            assert result.status == CrackStatus.SUCCESS
            assert result.cracked_password

    @pytest.mark.asyncio
    async def test_crack_auto_format(self, dummy_bcrypt_hash: Path, dummy_wordlist: Path) -> None:
        """Test la détection automatique du format."""
        john = JohnWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"Loaded 1 password hash (bcrypt)\n", b"")
        )
        mock_proc.returncode = 0

        with (
            patch.object(JohnWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await john.crack(str(dummy_bcrypt_hash), str(dummy_wordlist), fmt="auto")
            # Le type devrait être bcrypt
            assert result.hash_type == HashType.BCRYPT

    def test_build_args_with_format(self) -> None:
        """Test la construction des args avec format spécifique."""
        john = JohnWrapper()
        with patch.object(JohnWrapper, "available", new_callable=PropertyMock, return_value=True):
            args = john._build_args("/tmp/hash.txt", "/tmp/wl.txt", fmt="raw-md5")
            assert "--format" in args
            format_index = args.index("--format")
            assert args[format_index + 1] == "raw-md5"
            assert "--wordlist" in args
            wl_index = args.index("--wordlist")
            assert args[wl_index + 1] == "/tmp/wl.txt"

    def test_parse_show_output(self) -> None:
        """Test du parsing de john --show."""
        john = JohnWrapper()
        output = "Administrateur:password:1000:aad3b...\nuser2:123456:1001:...\n"
        results = john._parse_show_output(output)
        assert results["Administrateur"] == "password"
        assert results["user2"] == "123456"


# ══════════════════════════════════════════════════════════════════════════════
# Tests HydraWrapper
# ══════════════════════════════════════════════════════════════════════════════


class TestHydraWrapper:
    """Tests du wrapper Hydra."""

    def test_list_services(self) -> None:
        hydra = HydraWrapper()
        services = hydra.list_services()
        assert "ssh" in services
        assert "ftp" in services
        assert "http-get" in services
        assert "smb" in services
        assert "rdp" in services
        assert "mysql" in services

    @pytest.mark.asyncio
    async def test_crack_not_available(self) -> None:
        hydra = HydraWrapper()
        with patch.object(HydraWrapper, "available", new_callable=PropertyMock, return_value=False):
            result = await hydra.crack("target", "passwords.txt")
            assert result.status == CrackStatus.ERROR
            assert "pas installé" in result.error

    @pytest.mark.asyncio
    async def test_crack_unsupported_service(self) -> None:
        hydra = HydraWrapper()
        with patch.object(HydraWrapper, "available", new_callable=PropertyMock, return_value=True):
            result = await hydra.crack("target", "passwords.txt", service="unknown_proto")
            assert result.status == CrackStatus.ERROR
            assert "non supporté" in result.error

    @pytest.mark.asyncio
    async def test_crack_success(self) -> None:
        """Test un crack hydra réussi avec subprocess mocké."""
        hydra = HydraWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"[22][ssh] host: 192.168.1.10 login: root password: toor\n"
                b"[22][ssh] host: 192.168.1.10 login: admin password: admin123\n"
                b"1 of 1 target successfully completed, 2 valid passwords found\n",
                b"",
            )
        )
        mock_proc.returncode = 0

        with (
            patch.object(HydraWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await hydra.crack(
                "192.168.1.10", "passwords.txt",
                service="ssh", user="root",
            )
            assert result.status == CrackStatus.SUCCESS
            assert "root" in result.cracked_password
            assert "toor" in result.cracked_password

    @pytest.mark.asyncio
    async def test_crack_no_passwords_found(self) -> None:
        """Test hydra qui ne trouve aucun mot de passe."""
        hydra = HydraWrapper()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"1 of 1 target successfully completed, 0 valid passwords found\n",
                b"",
            )
        )
        mock_proc.returncode = 0

        with (
            patch.object(HydraWrapper, "available", new_callable=PropertyMock, return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await hydra.crack(
                "192.168.1.10", "passwords.txt", service="ssh",
            )
            assert result.status == CrackStatus.FAILED
            assert "aucun" in result.error.lower() or "sans trouver" in result.error.lower() or "Aucun" in result.error

    def test_parse_output(self) -> None:
        """Test du parsing de la sortie Hydra."""
        hydra = HydraWrapper()
        output = (
            "[22][ssh] host: 10.0.0.1 login: admin password: secret\n"
            "[3389][rdp] host: 10.0.0.2 login: Administrator password: Passw0rd\n"
        )
        logins = hydra._parse_output(output)
        assert len(logins) == 2
        assert logins[0].service == "ssh"
        assert logins[0].port == 22
        assert logins[0].host == "10.0.0.1"
        assert logins[0].login == "admin"
        assert logins[0].password == "secret"
        assert logins[1].service == "rdp"
        assert logins[1].port == 3389

    def test_build_args_with_userlist(self) -> None:
        """Test la construction des args avec userlist."""
        hydra = HydraWrapper()
        with patch.object(HydraWrapper, "available", new_callable=PropertyMock, return_value=True):
            args = hydra._build_args(
                "192.168.1.1",
                {"userlist": "/tmp/users.txt", "passwordlist": "/tmp/pass.txt"},
                service="ssh",
                tasks=8,
            )
            assert "-L" in args
            ul_index = args.index("-L")
            assert args[ul_index + 1] == "/tmp/users.txt"
            assert "-P" in args
            pl_index = args.index("-P")
            assert args[pl_index + 1] == "/tmp/pass.txt"


# ══════════════════════════════════════════════════════════════════════════════
# Tests d'intégration des wrappers
# ══════════════════════════════════════════════════════════════════════════════


class TestCrackingIntegrations:
    """Tests d'intégration mockés entre les wrappers."""

    def test_hashcat_modes_consistency(self) -> None:
        """Vérifie que les modes hashcat et les hash types sont cohérents."""
        for ht, mode in HASHCAT_MODES.items():
            if ht == HashType.SSH:
                continue  # SSH n'a pas de mode hashcat direct
            assert isinstance(mode, int)
            assert mode >= 0  # MD5 = 0 est valide

    def test_john_formats_consistency(self) -> None:
        """Vérifie que les formats john sont définis pour tous les types courants."""
        for ht in (HashType.NTLM, HashType.MD5, HashType.SHA256, HashType.SSH):
            assert ht in JOHN_FORMATS
            assert JOHN_FORMATS[ht]

    def test_wrapper_inheritance(self) -> None:
        """Vérifie que tous les wrappers héritent correctement de BaseCracker."""
        assert issubclass(HashcatWrapper, BaseCracker)
        assert issubclass(JohnWrapper, BaseCracker)
        assert issubclass(HydraWrapper, BaseCracker)

    def test_detect_hash_type_matches_modes(self) -> None:
        """Vérifie que detect_hash_type retourne les bons hashcat modes."""
        tests = {
            "Administrateur:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0": 1000,  # NTLM
            "5d41402abc4b2a76b9719d911017c592": 0,  # MD5
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": 100,  # SHA1
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": 1400,  # SHA256
            "$2b$12$LJ3m4ys3Lk0TSwHmsY.Eae7eM5U5gk2HjG5g5kY3k9k8k7k6k5k4": 3200,  # BCrypt
        }
        for hash_str, expected_mode in tests.items():
            info = detect_hash_type(hash_str)
            assert info.hashcat_mode == expected_mode, (
                f"Mismatch for {hash_str[:20]}...: "
                f"expected mode {expected_mode}, got {info.hashcat_mode}"
            )
