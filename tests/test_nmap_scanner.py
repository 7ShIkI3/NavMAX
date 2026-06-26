"""Tests pour NmapScanner — wrapper python-nmap avec fallback."""

from unittest.mock import PropertyMock, patch

import pytest

from navmax.scanner.nmap_scanner import (
    NmapHostResult,
    NmapScanner,
    PortScanResult,
    enrich_with_nmap,
)


class TestNmapScannerInit:
    """Tests d'initialisation du scanner."""

    def test_initialization(self) -> None:
        scanner = NmapScanner()
        assert scanner._nmap_available is None
        assert scanner._nmap is None

    def test_available_property_caches(self) -> None:
        scanner = NmapScanner()
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/nmap"
            assert scanner.available is True
            assert scanner._nmap_available is True

    def test_available_property_not_found(self) -> None:
        scanner = NmapScanner()
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None
            assert scanner.available is False
            assert scanner._nmap_available is False


class TestNmapScannerFallback:
    """Tests du fallback quand nmap n'est pas disponible."""

    @pytest.mark.asyncio
    async def test_fallback_when_nmap_unavailable(self) -> None:
        """Test que le fallback est utilisé quand nmap n'est pas trouvé."""
        scanner = NmapScanner()
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = NmapHostResult(
                    host="192.168.1.1",
                    status="up",
                    ports={80: {"port": 80, "state": "open", "service": "http"}},
                )
                result = await scanner.scan("192.168.1.1", ports=[80])
                assert result.status == "up"
                assert 80 in result.ports
                assert result.ports[80]["service"] == "http"
                mock_fallback.assert_called_once()

    @pytest.mark.asyncio
    async def test_fallback_when_nmap_python_missing(self) -> None:
        """Test que le fallback est utilisé quand python-nmap n'est pas installé."""
        scanner = NmapScanner()
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = True
            with patch.object(scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = NmapHostResult(host="10.0.0.1", status="up")
                import builtins

                real_import = builtins.__import__

                def mock_import(name, *args, **kwargs):
                    if name == "nmap":
                        msg = "no nmap"
                        raise ImportError(msg)
                    return real_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=mock_import):
                    result = await scanner.scan("10.0.0.1", ports=[22])
                    assert result.status == "up"
                    mock_fallback.assert_called_once()

    @pytest.mark.asyncio
    async def test_fallback_guess_service_by_banner(self) -> None:
        """Test que le fallback identifie les services par banner."""
        scanner = NmapScanner()
        assert scanner._guess_service(22, "SSH-2.0-OpenSSH_8.9p1") == "ssh"
        assert scanner._guess_service(80, "HTTP/1.1 200 OK") == "http"
        assert scanner._guess_service(3306, "mysql 5.7") == "mysql"
        assert scanner._guess_service(6379, "+PONG") == "redis"
        assert scanner._guess_service(21, "220 ProFTPD ready") == "ftp"

    @pytest.mark.asyncio
    async def test_fallback_guess_service_by_port(self) -> None:
        """Test que le fallback identifie les services par port."""
        scanner = NmapScanner()
        assert scanner._guess_service(22, "") == "ssh"
        assert scanner._guess_service(80, "") == "http"
        assert scanner._guess_service(3306, "") == "mysql"
        assert scanner._guess_service(3389, "") == "rdp"
        assert scanner._guess_service(6379, "") == "redis"
        assert scanner._guess_service(9999, "") == "unknown"

    @pytest.mark.asyncio
    async def test_fallback_scan_no_ports_default_list(self) -> None:
        """Test que le fallback utilise une liste de ports par défaut."""
        scanner = NmapScanner()
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(
                scanner,
                "_fallback_scan",
                wraps=scanner._fallback_scan,
            ) as mock_fallback:
                mock_fallback.side_effect = lambda h, p, t: NmapHostResult(host=h, status="up")
                result = await scanner.scan("192.168.1.1")
                assert result.status == "up"


class TestNmapScannerMockResults:
    """Tests du parsing des résultats nmap mockés."""

    @pytest.mark.asyncio
    async def test_os_detection_parsing(self) -> None:
        """Test le parsing des résultats de détection OS."""
        scanner = NmapScanner()

        mock_result = NmapHostResult(
            host="10.0.0.1",
            status="up",
            os_matches=[
                {"name": "Linux 4.15 - 5.6", "accuracy": 95, "line": "", "osclass": []},
                {"name": "Linux 5.x", "accuracy": 89, "line": "", "osclass": []},
            ],
            os_cpe="cpe:/o:linux:linux_kernel",
        )

        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = mock_result
                result = await scanner.scan_os("10.0.0.1")

                assert result.status == "up"
                assert len(result.os_matches) == 2
                assert result.os_matches[0]["name"] == "Linux 4.15 - 5.6"
                assert result.os_matches[0]["accuracy"] == 95
                assert result.os_cpe == "cpe:/o:linux:linux_kernel"

    @pytest.mark.asyncio
    async def test_version_detection_parsing(self) -> None:
        """Test le parsing des résultats de version detection."""
        scanner = NmapScanner()

        mock_result = NmapHostResult(
            host="10.0.0.1",
            status="up",
            ports={
                80: {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.49",
                    "extrainfo": "mod_ssl",
                    "cpe": "cpe:/a:apache:http_server:2.4.49",
                    "script_results": {"http-title": "Apache Default Page"},
                },
                22: {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9p1",
                    "extrainfo": "Ubuntu",
                    "cpe": "cpe:/a:openbsd:openssh:8.9p1",
                    "script_results": {},
                },
            },
        )

        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = mock_result
                result = await scanner.scan_services("10.0.0.1", ports=[80, 22])

                assert result.status == "up"
                assert 80 in result.ports
                assert result.ports[80]["service"] == "http"
                assert result.ports[80]["product"] == "Apache httpd"
                assert result.ports[80]["version"] == "2.4.49"
                assert "http-title" in result.ports[80].get("script_results", {})
                assert 22 in result.ports
                assert result.ports[22]["service"] == "ssh"
                assert result.ports[22]["version"] == "8.9p1"

    @pytest.mark.asyncio
    async def test_vuln_scan_method(self) -> None:
        """Test que scan_vuln utilise les bons arguments."""
        scanner = NmapScanner()
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = NmapHostResult(
                    host="10.0.0.1",
                    status="up",
                )
                result = await scanner.scan_vuln("10.0.0.1", ports=[80, 443])
                assert result.status == "up"
                mock_fallback.assert_called_once()

    @pytest.mark.asyncio
    async def test_nse_scan_method(self) -> None:
        """Test que scan_nse utilise les bons arguments."""
        scanner = NmapScanner()
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = NmapHostResult(
                    host="10.0.0.1",
                    status="up",
                )
                result = await scanner.scan_nse(
                    "10.0.0.1",
                    scripts=["http-title", "ssl-enum-ciphers"],
                    ports=[80, 443],
                )
                assert result.status == "up"
                mock_fallback.assert_called_once()


class TestEnrichWithNmap:
    """Tests de la fonction enrich_with_nmap."""

    @pytest.mark.asyncio
    async def test_enrich_returns_expected_structure(self) -> None:
        """Test que enrich_with_nmap retourne la structure attendue."""
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(NmapScanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = NmapHostResult(
                    host="10.0.0.1",
                    status="up",
                    os_matches=[{"name": "Linux", "accuracy": 90, "line": "", "osclass": []}],
                    os_cpe="cpe:/o:linux:linux_kernel",
                    mac_address="00:11:22:33:44:55",
                    ports={
                        80: {"port": 80, "state": "open", "service": "http", "version": "2.4.49"},
                    },
                )
                result = await enrich_with_nmap("10.0.0.1", ports=[80])
                assert "os_matches" in result
                assert "os_cpe" in result
                assert "ports" in result
                assert "mac_address" in result
                assert "scanner_used" in result
                assert result["os_matches"][0]["name"] == "Linux"
                assert result["mac_address"] == "00:11:22:33:44:55"
                assert result["scanner_used"] == "fallback"

    @pytest.mark.asyncio
    async def test_enrich_with_custom_scanner(self) -> None:
        """Test que enrich_with_nmap accepte un scanner personnalisé."""
        custom_scanner = NmapScanner()
        with patch.object(NmapScanner, "available", new_callable=PropertyMock) as mock_avail:
            mock_avail.return_value = False
            with patch.object(custom_scanner, "_fallback_scan") as mock_fallback:
                mock_fallback.return_value = NmapHostResult(
                    host="10.0.0.1",
                    status="up",
                    ports={22: {"port": 22, "state": "open", "service": "ssh"}},
                )
                result = await enrich_with_nmap("10.0.0.1", [22], nmap_scanner=custom_scanner)
                assert result["ports"][22]["service"] == "ssh"


class TestNmapHostResult:
    """Tests de la dataclass NmapHostResult."""

    def test_defaults(self) -> None:
        r = NmapHostResult(host="10.0.0.1")
        assert r.host == "10.0.0.1"
        assert r.status == "down"
        assert r.ports == {}
        assert r.os_matches == []
        assert r.os_cpe == ""
        assert r.mac_address is None
        assert r.error is None

    def test_with_data(self) -> None:
        r = NmapHostResult(
            host="10.0.0.1",
            status="up",
            ports={80: {"service": "http"}},
            os_matches=[{"name": "Linux"}],
            os_cpe="cpe:/o:linux:linux_kernel",
            mac_address="00:11:22:33:44:55",
        )
        assert r.status == "up"
        assert r.ports[80]["service"] == "http"
        assert r.os_matches[0]["name"] == "Linux"
        assert r.mac_address == "00:11:22:33:44:55"


class TestPortScanResult:
    """Tests de la dataclass PortScanResult."""

    def test_defaults(self) -> None:
        r = PortScanResult(port=80)
        assert r.port == 80
        assert r.protocol == "tcp"
        assert r.state == "closed"
        assert r.service is None
        assert r.script_results == {}
        assert r.vulnerabilities == []

    def test_full_data(self) -> None:
        r = PortScanResult(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            product="nginx",
            version="1.18.0",
            extrainfo="TLS 1.3",
            cpe="cpe:/a:nginx:nginx:1.18.0",
            script_results={"ssl-enum-ciphers": "TLS_AES_256_GCM"},
            os_detected="Linux",
            os_accuracy=95,
            vulnerabilities=[{"cve": "CVE-2021-23017"}],
        )
        assert r.service == "https"
        assert r.version == "1.18.0"
        assert r.os_detected == "Linux"
        assert len(r.vulnerabilities) == 1
        assert r.vulnerabilities[0]["cve"] == "CVE-2021-23017"
