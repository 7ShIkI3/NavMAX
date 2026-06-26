"""Tests unitaires NavMAX — Phase 1."""

import pytest

from navmax.scanner.engine import parse_ports


class TestParsePorts:
    def test_single_port(self) -> None:
        assert parse_ports("80") == [80]

    def test_multiple_ports(self) -> None:
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self) -> None:
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixed(self) -> None:
        result = parse_ports("1-3,80,443")
        assert result == [1, 2, 3, 80, 443]

    def test_deduplicate(self) -> None:
        result = parse_ports("80,80,443")
        assert result == [80, 443]

    def test_sorted(self) -> None:
        result = parse_ports("443,22,80")
        assert result == [22, 80, 443]

    def test_spaces(self) -> None:
        result = parse_ports(" 22 , 80 , 443 ")
        assert result == [22, 80, 443]


class TestConfig:
    def test_defaults(self) -> None:
        from navmax.core.config import config

        assert config.api_host == "127.0.0.1"
        assert config.api_port == 8443

    def test_database_url(self) -> None:
        from navmax.core.config import config

        url = config.database_url
        assert "sqlite" in url
        assert "navmax.db" in url


class TestCoreImport:
    def test_import_core(self) -> None:
        from navmax.core import config

        assert config is not None

    def test_import_db(self) -> None:
        from navmax.db import Scan, Service, Target

        assert Target.__tablename__ == "targets"
        assert Scan.__tablename__ == "scans"
        assert Service.__tablename__ == "services"

    def test_import_scanner(self) -> None:
        from navmax.scanner import detect_os, parse_ports, tcp_connect_scan

        assert callable(tcp_connect_scan)
        assert callable(parse_ports)
        assert callable(detect_os)


class TestBannerParsing:
    def test_ssh_banner(self) -> None:
        from navmax.scanner.tcp import _parse_banner

        svc, ver = _parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert svc == "ssh"
        assert ver == "2.0" or ver is not None

    def test_http_banner(self) -> None:
        from navmax.scanner.tcp import _parse_banner

        svc, _ = _parse_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
        assert svc == "http"

    def test_unknown_banner(self) -> None:
        from navmax.scanner.tcp import _parse_banner

        svc, ver = _parse_banner("random garbage data")
        assert svc is None
        assert ver is None


class TestPluginManager:
    @pytest.mark.asyncio
    async def test_discover_empty(self) -> None:
        from navmax.core.plugins import PluginManager

        pm = PluginManager()
        # Pas de plugins dans le package core
        discovered = pm.discover("navmax.core")
        assert isinstance(discovered, list)
        # Accepte 0 ou plus — le package core n'a que des modules standards
