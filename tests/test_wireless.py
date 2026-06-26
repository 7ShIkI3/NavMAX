"""Tests pour le module Wireless.

Teste :
- Les modèles Pydantic (WiFiNetwork, BLEDevice, Handshake, HardwareCapability)
- Le parsing CSV d'airodump-ng
- La détection matérielle (check_hardware) avec mocks
- Les opérations WiFi (scan, deauth, capture) avec mocks subprocess
- Le scanner BLE (scan, connect, read/write) avec mocks
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, call, mock_open, patch

import pytest

from navmax.wireless.base import (
    BLEDevice,
    BaseWirelessScanner,
    Handshake,
    HardwareCapability,
    WiFiNetwork,
    WirelessTech,
)

# ═══════════════════════════════════════════════════════════════
# Modèles Pydantic
# ═══════════════════════════════════════════════════════════════


class TestWiFiNetwork:
    """Tests de la dataclass WiFiNetwork."""

    def test_minimal(self) -> None:
        net = WiFiNetwork(bssid="00:11:22:33:44:55", essid="TestNet")
        assert net.bssid == "00:11:22:33:44:55"
        assert net.essid == "TestNet"
        assert net.channel == 0
        assert net.signal == 0
        assert net.encryption == ""

    def test_full(self) -> None:
        net = WiFiNetwork(
            bssid="AA:BB:CC:DD:EE:FF",
            essid="MyWiFi",
            channel=6,
            signal=-45,
            encryption="WPA2",
            privacy="CCMP",
            cipher="AES",
            authentication="PSK",
            beacon_interval=100,
        )
        assert net.channel == 6
        assert net.signal == -45
        assert net.encryption == "WPA2"
        assert net.privacy == "CCMP"
        assert net.cipher == "AES"
        assert net.authentication == "PSK"
        assert net.beacon_interval == 100

    def test_missing_essid_handling(self) -> None:
        # Certains APs masquent leur SSID → chaîne vide
        net = WiFiNetwork(bssid="00:00:00:00:00:01", essid="")
        assert net.essid == ""


class TestBLEDevice:
    """Tests de la dataclass BLEDevice."""

    def test_minimal(self) -> None:
        dev = BLEDevice(address="AA:BB:CC:DD:EE:FF")
        assert dev.address == "AA:BB:CC:DD:EE:FF"
        assert dev.name == ""
        assert dev.rssi == 0
        assert dev.uuid_services == []

    def test_full(self) -> None:
        dev = BLEDevice(
            address="11:22:33:44:55:66",
            name="SensorTag",
            rssi=-70,
            uuid_services=["180A", "180F"],
            manufacturer_data={0x004C: "010203"},
            tx_power=4,
        )
        assert dev.name == "SensorTag"
        assert dev.rssi == -70
        assert len(dev.uuid_services) == 2
        assert dev.manufacturer_data[0x004C] == "010203"
        assert dev.tx_power == 4


class TestHandshake:
    """Tests de la dataclass Handshake."""

    def test_minimal(self) -> None:
        hs = Handshake(bssid="00:11:22:33:44:55")
        assert hs.bssid == "00:11:22:33:44:55"
        assert not hs.complete

    def test_full(self) -> None:
        hs = Handshake(
            bssid="AA:BB:CC:DD:EE:FF",
            station="11:22:33:44:55:66",
            cap_file="/tmp/capture.cap",
            hash_file="/tmp/capture.22000",
            pmkid="abcdef1234567890",
            complete=True,
            ap_name="Test_AP",
            encrypted=True,
        )
        assert hs.station == "11:22:33:44:55:66"
        assert hs.cap_file == "/tmp/capture.cap"
        assert hs.hash_file == "/tmp/capture.22000"
        assert hs.pmkid == "abcdef1234567890"
        assert hs.complete
        assert hs.ap_name == "Test_AP"
        assert hs.encrypted


class TestHardwareCapability:
    """Tests de la dataclass HardwareCapability."""

    def test_defaults(self) -> None:
        hw = HardwareCapability()
        assert not hw.available
        assert hw.interfaces == []
        assert not hw.monitor_mode
        assert not hw.packet_injection
        assert not hw.ble_support
        assert hw.tech == WirelessTech.NONE
        assert hw.error is None

    def test_wifi_only(self) -> None:
        hw = HardwareCapability(
            available=True,
            interfaces=["wlan0"],
            monitor_mode=True,
            packet_injection=True,
            tech=WirelessTech.WIFI,
        )
        assert hw.available
        assert hw.tech == WirelessTech.WIFI
        assert hw.monitor_mode
        assert hw.packet_injection

    def test_both(self) -> None:
        hw = HardwareCapability(
            available=True,
            interfaces=["wlan0"],
            monitor_mode=True,
            packet_injection=True,
            ble_support=True,
            tech=WirelessTech.BOTH,
        )
        assert hw.tech == WirelessTech.BOTH

    def test_error_state(self) -> None:
        hw = HardwareCapability(
            available=False,
            error="Aucun adaptateur trouvé",
        )
        assert hw.error == "Aucun adaptateur trouvé"


# ═══════════════════════════════════════════════════════════════
# BaseWirelessScanner (classe abstraite)
# ═══════════════════════════════════════════════════════════════


class TestBaseWirelessScanner:
    """Vérifie que BaseWirelessScanner ne peut pas être instancié directement."""

    def test_abstract_cannot_instantiate(self) -> None:
        with pytest.raises(TypeError):
            BaseWirelessScanner()  # type: ignore[abstract]

    def test_concrete_implementation(self) -> None:
        """Une sous-classe concrète doit pouvoir être instanciée."""

        class ConcreteScanner(BaseWirelessScanner):
            def check_hardware(self) -> HardwareCapability:
                return HardwareCapability()

            def scan(self, timeout: int = 15) -> list:
                return []

        scanner = ConcreteScanner()
        hw = scanner.check_hardware()
        assert not hw.available
        assert scanner.scan() == []


# ═══════════════════════════════════════════════════════════════
# Parsing CSV airodump-ng
# ═══════════════════════════════════════════════════════════════


class TestAirodumpCSVParsing:
    """Teste _parse_airodump_csv avec des données CSV simulées."""

    @pytest.fixture
    def sample_csv(self) -> str:
        return (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
            "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, 2025-01-01 10:00:00, 2025-01-01 10:05:00, 6, "
            "130, WPA2, CCMP, PSK, -45, 120, 0, 0.0.0.0, 7, TestNet, 1\n"
            "AA:BB:CC:DD:EE:FF, 2025-01-01 10:00:00, 2025-01-01 10:05:00, 11, "
            "54, WPA2, TKIP, PSK, -67, 50, 0, 0.0.0.0, 0, , 0\n"
            "11:22:33:44:55:66, 2025-01-01 10:00:00, 2025-01-01 10:05:00, 1, "
            "300, WPA3, CCMP, SAE, -30, 200, 0, 0.0.0.0, 8, SecureNet, 1\n"
        )

    def test_parse_normal_csv(self, sample_csv: str) -> None:
        from navmax.wireless.wifi_scanner import _parse_airodump_csv

        networks = _parse_airodump_csv(sample_csv)
        assert len(networks) == 3

        # Premier réseau
        assert networks[0].bssid == "00:11:22:33:44:55"
        assert networks[0].essid == "TestNet"
        assert networks[0].channel == 6
        assert networks[0].signal == -45
        assert networks[0].encryption == "WPA2"

        # Deuxième réseau (SSID masqué → chaîne vide)
        assert networks[1].bssid == "AA:BB:CC:DD:EE:FF"
        assert networks[1].essid == ""
        assert networks[1].channel == 11
        assert networks[1].signal == -67

        # Troisième réseau
        assert networks[2].bssid == "11:22:33:44:55:66"
        assert networks[2].essid == "SecureNet"
        assert networks[2].channel == 1
        assert networks[2].signal == -30
        assert networks[2].encryption == "WPA3"

    def test_parse_empty_csv(self) -> None:
        from navmax.wireless.wifi_scanner import _parse_airodump_csv

        # CSV vide
        networks = _parse_airodump_csv("")
        assert networks == []

    def test_parse_csv_with_only_headers(self) -> None:
        from navmax.wireless.wifi_scanner import _parse_airodump_csv

        csv_headers = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
            "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        )
        networks = _parse_airodump_csv(csv_headers)
        assert networks == []

    def test_parse_malformed_row(self) -> None:
        from navmax.wireless.wifi_scanner import _parse_airodump_csv

        # Ligne avec channel non numérique
        csv_data = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
            "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, ..., ..., invalid, 130, WPA2, CCMP, PSK, -50, ...\n"
        )
        networks = _parse_airodump_csv(csv_data)
        assert len(networks) == 1
        assert networks[0].channel == 0  # fallback
        assert networks[0].signal == -50


# ═══════════════════════════════════════════════════════════════
# WiFiScanner — Détection matérielle (mocked)
# ═══════════════════════════════════════════════════════════════


class TestWiFiScannerCheckHardware:
    """Teste WiFiScanner.check_hardware() avec subprocess mocké."""

    @pytest.fixture
    def scanner(self) -> object:
        from navmax.wireless.wifi_scanner import WiFiScanner

        return WiFiScanner(interface="wlan0")

    def test_airmon_detects_interfaces(self, scanner: object) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        # Simule la sortie d'airmon-ng
        airmon_output = (
            "Phy\tInterface\tDriver\t\tChipset\n"
            "phy0\twlan0\t\tath9k\t\tQualcomm Atheros\n"
        )

        with (
            patch("navmax.wireless.wifi_scanner._check_binary") as mock_check,
            patch("subprocess.run") as mock_run,
        ):
            # airmon-ng trouvé, iwconfig et iw absents
            mock_check.side_effect = lambda name: {
                "airmon-ng": "/usr/sbin/airmon-ng",
                "iwconfig": None,
                "iw": None,
            }.get(name)

            mock_run.return_value = MagicMock(
                stdout=airmon_output,
                stderr="",
                returncode=0,
            )

            hw = scanner.check_hardware()
            assert hw.available
            assert "wlan0" in hw.interfaces
            # Sans iw, monitor_mode et injection restent à False
            assert not hw.monitor_mode

    def test_iwconfig_fallback(self, scanner: object) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        with (
            patch("navmax.wireless.wifi_scanner._check_binary") as mock_check,
            patch("subprocess.run") as mock_run,
        ):
            # airmon-ng absent, iwconfig présent, iw absent
            mock_check.side_effect = lambda name: {
                "airmon-ng": None,
                "iwconfig": "/usr/sbin/iwconfig",
                "iw": None,
            }.get(name)

            mock_run.return_value = MagicMock(
                stdout=(
                    "lo        no wireless extensions.\n"
                    "wlan0     IEEE 802.11  ESSID:\"\"\n"
                ),
                stderr="",
                returncode=0,
            )

            hw = scanner.check_hardware()
            assert hw.available
            assert "wlan0" in hw.interfaces

    def test_no_interfaces(self, scanner: object) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        with (
            patch("navmax.wireless.wifi_scanner._check_binary") as mock_check,
            patch("subprocess.run") as mock_run,
        ):
            mock_check.side_effect = lambda name: {
                "airmon-ng": None,
                "iwconfig": None,
                "iw": None,
            }.get(name)

            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)

            hw = scanner.check_hardware()
            assert not hw.available
            assert hw.interfaces == []
            assert hw.tech == WirelessTech.NONE

    def test_ble_support_detected(self, scanner: object) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        with (
            patch("navmax.wireless.wifi_scanner._check_binary") as mock_check,
            patch("subprocess.run") as mock_run,
            patch.dict("sys.modules", {"bleak": MagicMock()}),
        ):
            mock_check.side_effect = lambda name: {
                "airmon-ng": "/usr/sbin/airmon-ng",
                "iwconfig": None,
                "iw": None,
            }.get(name)

            mock_run.return_value = MagicMock(
                stdout="phy0\twlan0\tath9k\tQualcomm Atheros\n",
                stderr="",
                returncode=0,
            )

            hw = scanner.check_hardware()
            assert hw.ble_support
            assert hw.tech in (WirelessTech.BOTH, WirelessTech.WIFI)


# ═══════════════════════════════════════════════════════════════
# WiFiScanner — Opérations (mocked)
# ═══════════════════════════════════════════════════════════════


class TestWiFiScannerOperations:
    """Teste les opérations WiFi avec subprocess mocké."""

    @pytest.fixture
    def scanner(self) -> object:
        from navmax.wireless.wifi_scanner import WiFiScanner

        return WiFiScanner(interface="wlan0")

    @patch("navmax.wireless.wifi_scanner._require_binary")
    @patch("navmax.wireless.wifi_scanner.subprocess.Popen")
    @patch("navmax.wireless.wifi_scanner.time.sleep")
    def test_scan_networks(
        self,
        mock_sleep: MagicMock,
        mock_popen: MagicMock,
        mock_require: MagicMock,
        scanner: object,
        tmp_path: Path,
    ) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        # Création d'un faux fichier CSV dans un répertoire temporaire
        csv_content = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
            "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, ..., ..., 6, 130, WPA2, CCMP, PSK, -45, 120, ...\n"
        )

        csv_file = tmp_path / "scan-01.csv"
        csv_file.write_text(csv_content)

        # On mocke tempfile.TemporaryDirectory pour qu'il utilise tmp_path
        with patch("navmax.wireless.wifi_scanner.tempfile.TemporaryDirectory") as mock_tmpdir:
            mock_tmpdir.return_value.__enter__.return_value = str(tmp_path)
            mock_tmpdir.return_value.__exit__.return_value = None

            mock_proc = MagicMock()
            mock_popen.return_value = mock_proc

            networks = scanner.scan_networks(timeout=2)
            assert len(networks) == 1
            assert networks[0].bssid == "00:11:22:33:44:55"
            assert networks[0].channel == 6
            assert networks[0].signal == -45
            assert networks[0].encryption == "WPA2"

    @patch("navmax.wireless.wifi_scanner._require_binary")
    @patch("navmax.wireless.wifi_scanner.subprocess.run")
    def test_enable_monitor_mode(
        self,
        mock_run: MagicMock,
        mock_require: MagicMock,
        scanner: object,
    ) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        mock_require.return_value = "/usr/sbin/airmon-ng"
        mock_run.return_value = MagicMock(
            stdout="(monitor mode enabled on wlan0mon)",
            stderr="",
            returncode=0,
        )

        result = scanner.enable_monitor_mode("wlan0")
        assert result
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "airmon-ng" in str(args)
        assert "start" in args

    @patch("navmax.wireless.wifi_scanner._require_binary")
    @patch("navmax.wireless.wifi_scanner.subprocess.run")
    def test_deauth_client(
        self,
        mock_run: MagicMock,
        mock_require: MagicMock,
        scanner: object,
    ) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        scanner._monitor_interface = "wlan0mon"

        mock_require.return_value = "/usr/sbin/aireplay-ng"
        mock_run.return_value = MagicMock(
            stdout="5 packets sent to 00:11:22:33:44:55",
            stderr="",
            returncode=0,
        )

        sent = scanner.deauth_client(
            bssid="00:11:22:33:44:55",
            client="66:77:88:99:AA:BB",
            count=5,
        )
        assert sent == 5
        args = mock_run.call_args[0][0]
        assert "--deauth" in args
        assert "5" in args

    @patch("navmax.wireless.wifi_scanner._require_binary")
    @patch("navmax.wireless.wifi_scanner.subprocess.run")
    def test_deauth_broadcast(
        self,
        mock_run: MagicMock,
        mock_require: MagicMock,
        scanner: object,
    ) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        scanner._monitor_interface = "wlan0mon"

        mock_require.return_value = "/usr/sbin/aireplay-ng"
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="",
            returncode=0,
        )

        # En broadcast, sans pattern "packets" dans la sortie → retourne count
        sent = scanner.deauth_client(
            bssid="00:11:22:33:44:55",
            client="FF:FF:FF:FF:FF:FF",
            count=3,
        )
        assert sent == 3

    @patch("navmax.wireless.wifi_scanner._require_binary")
    @patch("navmax.wireless.wifi_scanner.subprocess.Popen")
    @patch("navmax.wireless.wifi_scanner.time.sleep")
    def test_capture_handshake(
        self,
        mock_sleep: MagicMock,
        mock_popen: MagicMock,
        mock_require: MagicMock,
        scanner: object,
        tmp_path: Path,
    ) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        # Créer un faux .cap
        cap_file = tmp_path / "handshake.cap"
        cap_file.write_text("fakepcapdata")

        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc

        # On mocke la recherche de fichier après capture
        with patch("pathlib.Path.glob") as mock_glob:
            mock_glob.return_value = [cap_file]

            hs = scanner.capture_handshake(
                bssid="00:11:22:33:44:55",
                channel=6,
                output_file=str(cap_file),
                timeout=2,
            )
            assert hs.bssid == "00:11:22:33:44:55"
            assert hs.cap_file == str(cap_file)
            assert hs.complete

    def test_crack_handshake_no_wordlist(self, scanner: object) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        with pytest.raises(FileNotFoundError):
            scanner.crack_handshake(
                handshake_file="/nonexistent/handshake.22000",
                wordlist="/nonexistent/wordlist.txt",
            )


# ═══════════════════════════════════════════════════════════════
# WiFiScanner — exceptions et cas aux limites
# ═══════════════════════════════════════════════════════════════


class TestWiFiScannerExceptions:
    """Teste la gestion des erreurs du WiFiScanner."""

    def test_scan_without_interface(self) -> None:
        """WiFiScanner sans interface doit lever une erreur."""
        from navmax.wireless.wifi_scanner import WiFiScanner

        scanner = WiFiScanner(interface=None)

        with (
            patch("navmax.wireless.wifi_scanner._check_binary") as mock_check,
            patch("navmax.wireless.wifi_scanner._require_binary") as mock_require,
            patch("navmax.wireless.wifi_scanner.subprocess.run") as mock_run,
        ):
            mock_check.side_effect = lambda name: {
                "airmon-ng": None,
                "iwconfig": None,
                "iw": None,
            }.get(name)

            mock_require.return_value = "/usr/sbin/airodump-ng"
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)

            with pytest.raises(RuntimeError, match="Aucune interface sans-fil détectée"):
                scanner.scan_networks(timeout=1)

    @patch("navmax.wireless.wifi_scanner._require_binary")
    @patch("navmax.wireless.wifi_scanner.subprocess.Popen")
    def test_scan_csv_not_found(
        self,
        mock_popen: MagicMock,
        mock_require: MagicMock,
        tmp_path: Path,
    ) -> None:
        from navmax.wireless.wifi_scanner import WiFiScanner

        scanner = WiFiScanner(interface="wlan0")
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        mock_require.return_value = "/usr/sbin/airodump-ng"

        with patch("navmax.wireless.wifi_scanner.tempfile.TemporaryDirectory") as mock_tmpdir:
            mock_tmpdir.return_value.__enter__.return_value = str(tmp_path)
            mock_tmpdir.return_value.__exit__.return_value = None

            with pytest.raises(RuntimeError, match="Aucun fichier CSV"):
                scanner.scan_networks(timeout=1)


# ═══════════════════════════════════════════════════════════════
# BLEScanner — basique avec bleak mocké
# ═══════════════════════════════════════════════════════════════


class TestBLEScannerCheckHardware:
    """Teste BLEScanner.check_hardware()."""

    def test_bleak_not_installed(self) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        with patch("navmax.wireless.ble_scanner._is_bleak_available", return_value=False):
            scanner = BLEScanner()
            hw = scanner.check_hardware()
            assert not hw.available
            assert not hw.ble_support
            assert hw.error == "bleak n'est pas installé"

    def test_bleak_installed_no_adapter(self) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_bleak = MagicMock()
        mock_bleak.BleakScanner.discover.side_effect = Exception("No adapter found")

        with (
            patch("navmax.wireless.ble_scanner._is_bleak_available", return_value=True),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            scanner = BLEScanner()
            hw = scanner.check_hardware()
            assert not hw.available
            assert hw.ble_support  # bleak installé
            assert "Adaptateur BLE non détecté" in (hw.error or "")

    def test_bleak_working(self) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_bleak = MagicMock()
        mock_bleak.BleakScanner.discover.return_value = {}

        with (
            patch("navmax.wireless.ble_scanner._is_bleak_available", return_value=True),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            scanner = BLEScanner()
            hw = scanner.check_hardware()
            assert hw.available
            assert hw.ble_support
            assert hw.tech == WirelessTech.BLE


class TestBLEScannerAsync:
    """Tests asynchrones du BLEScanner avec bleak mocké."""

    @pytest.fixture
    def scanner(self) -> object:
        from navmax.wireless.ble_scanner import BLEScanner
        return BLEScanner()

    @pytest.fixture
    def mock_bleak(self) -> MagicMock:
        """Crée un mock bleak injectable dans sys.modules."""
        mock_bleak = MagicMock()
        mock_bleak.BleakScanner = MagicMock()
        mock_bleak.BleakClient = MagicMock()
        return mock_bleak

    @pytest.mark.asyncio
    async def test_scan_devices_empty(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_scanner_instance = AsyncMock()
        mock_scanner_instance.discover = AsyncMock(return_value={})
        mock_bleak.BleakScanner.return_value = mock_scanner_instance

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            devices = await scanner.scan_devices(timeout=5)
            assert devices == []

    @pytest.mark.asyncio
    async def test_scan_devices_with_results(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        # Simuler un périphérique BLE
        mock_device = MagicMock()
        mock_device.address = "AA:BB:CC:DD:EE:FF"
        mock_device.name = "TestTag"
        mock_device.rssi = -60

        mock_adv = MagicMock()
        mock_adv.service_uuids = ["180A", "180F"]
        mock_adv.manufacturer_data = {0x004C: bytes([0x01, 0x02, 0x03])}

        mock_scanner_instance = AsyncMock()
        mock_scanner_instance.discover = AsyncMock(return_value={
            "AA:BB:CC:DD:EE:FF": (mock_device, mock_adv),
        })
        mock_bleak.BleakScanner.return_value = mock_scanner_instance

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            devices = await scanner.scan_devices(timeout=5)
            assert len(devices) == 1
            assert devices[0].address == "AA:BB:CC:DD:EE:FF"
            assert devices[0].name == "TestTag"
            assert devices[0].rssi == -60
            assert "180A" in devices[0].uuid_services
            assert 0x004C in devices[0].manufacturer_data

    @pytest.mark.asyncio
    async def test_scan_devices_raises_if_bleak_missing(self, scanner: object) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        with patch("navmax.wireless.ble_scanner._require_bleak") as mock_require:
            mock_require.side_effect = ImportError("bleak is not installed")
            with pytest.raises(ImportError):
                await scanner.scan_devices(timeout=1)

    @pytest.mark.asyncio
    async def test_connect_device_success(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_client = AsyncMock()
        mock_bleak.BleakClient.return_value = mock_client

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            client = await scanner.connect_device("AA:BB:CC:DD:EE:FF")
            mock_client.connect.assert_awaited_once()
            assert client is mock_client

    @pytest.mark.asyncio
    async def test_connect_device_failure(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_client = AsyncMock()
        mock_client.connect.side_effect = Exception("Connection timeout")
        mock_bleak.BleakClient.return_value = mock_client

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            with pytest.raises(ConnectionError, match="Échec de connexion"):
                await scanner.connect_device("BB:CC:DD:EE:FF:00")

    @pytest.mark.asyncio
    async def test_read_characteristic(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.read_gatt_char.return_value = b"\x01\x02\x03"
        mock_bleak.BleakClient.return_value = mock_client

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            data = await scanner.read_characteristic(
                "AA:BB:CC:DD:EE:FF",
                "00002a00-0000-1000-8000-00805f9b34fb",
            )
            assert data == b"\x01\x02\x03"

    @pytest.mark.asyncio
    async def test_write_characteristic(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_bleak.BleakClient.return_value = mock_client

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            await scanner.write_characteristic(
                "AA:BB:CC:DD:EE:FF",
                "00002a00-0000-1000-8000-00805f9b34fb",
                b"\x00\x01",
                response=True,
            )
            mock_client.write_gatt_char.assert_awaited_once_with(
                "00002a00-0000-1000-8000-00805f9b34fb",
                b"\x00\x01",
                response=True,
            )

    @pytest.mark.asyncio
    async def test_list_services(self, scanner: object, mock_bleak: MagicMock) -> None:
        from navmax.wireless.ble_scanner import BLEScanner

        # Simuler un service avec une caractéristique
        mock_char = MagicMock()
        mock_char.uuid = "00002a00-0000-1000-8000-00805f9b34fb"
        mock_char.properties = ["read", "write"]

        mock_service = MagicMock()
        mock_service.uuid = "00001800-0000-1000-8000-00805f9b34fb"
        mock_service.description = "Generic Access"
        mock_service.characteristics = [mock_char]

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        # Mock l'itération sur les services
        mock_client.services.__iter__.return_value = iter([mock_service])
        mock_bleak.BleakClient.return_value = mock_client

        with (
            patch("navmax.wireless.ble_scanner._require_bleak"),
            patch.dict("sys.modules", {"bleak": mock_bleak}),
        ):
            services = await scanner.list_services("AA:BB:CC:DD:EE:FF")
            assert len(services) == 1
            assert "00001800" in services[0]
            assert "Generic Access" in services[0]


# ═══════════════════════════════════════════════════════════════
# _check_binary / _require_binary
# ═══════════════════════════════════════════════════════════════


class TestBinaryCheck:
    """Teste les fonctions utilitaires de vérification des binaires."""

    def test_check_binary_found(self) -> None:
        from navmax.wireless.wifi_scanner import _check_binary

        # shutil.which("python") devrait trouver python
        path = _check_binary("python")
        assert path is not None

    def test_check_binary_not_found(self) -> None:
        from navmax.wireless.wifi_scanner import _check_binary

        path = _check_binary("nonexistent_binary_xyz")
        assert path is None

    def test_require_binary_found(self) -> None:
        from navmax.wireless.wifi_scanner import _require_binary

        path = _require_binary("python")
        assert path is not None

    def test_require_binary_not_found(self) -> None:
        from navmax.wireless.wifi_scanner import _require_binary

        with pytest.raises(FileNotFoundError, match="Binaire requis introuvable"):
            _require_binary("nonexistent_binary_xyz")


# ═══════════════════════════════════════════════════════════════
# Intégration des sous-modules dans le package wireless
# ═══════════════════════════════════════════════════════════════


class TestWirelessPackage:
    """Vérifie que le package wireless exporte correctement ses symboles."""

    def test_import_wireless(self) -> None:
        import navmax.wireless as wireless

        assert hasattr(wireless, "WiFiScanner")
        assert hasattr(wireless, "BLEScanner")
        assert hasattr(wireless, "WiFiNetwork")
        assert hasattr(wireless, "BLEDevice")
        assert hasattr(wireless, "Handshake")
        assert hasattr(wireless, "HardwareCapability")
        assert hasattr(wireless, "WirelessTech")
        assert hasattr(wireless, "BaseWirelessScanner")

    def test_wifi_scanner_subclass(self) -> None:
        from navmax.wireless import WiFiScanner
        from navmax.wireless.base import BaseWirelessScanner

        assert issubclass(WiFiScanner, BaseWirelessScanner)

    def test_ble_scanner_subclass(self) -> None:
        from navmax.wireless import BLEScanner
        from navmax.wireless.base import BaseWirelessScanner

        assert issubclass(BLEScanner, BaseWirelessScanner)
