"""
Tests pour ContextualScanEngine et VulnDatabase.
"""

import pytest
from navmax.scanner.contextual import (
    ContextualScanEngine, ScanResult, _identify_service, _guess_by_port,
)
from navmax.scanner.vuln_db import VulnDatabase


# ── Service Identification ─────────────────────────────────────

class TestServiceIdentification:
    def test_ssh_banner(self):
        svc, ver = _identify_service(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        assert svc == "ssh"
        assert ver == "SSH-2.0-OpenSSH_8.9p1"

    def test_apache_banner(self):
        svc, ver = _identify_service(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49")
        assert svc == "http"

    def test_nginx_banner(self):
        svc, ver = _identify_service(80, "HTTP/1.1 404 Not Found\r\nServer: nginx/1.18.0")
        assert svc == "http"

    def test_mysql_banner(self):
        svc, ver = _identify_service(3306, "5.5.5-10.5.12-MariaDB\x00...")
        assert svc == "mysql"

    def test_redis_ping(self):
        svc, ver = _identify_service(6379, "+PONG\r\n")
        assert svc == "redis"

    def test_redis_error(self):
        svc, ver = _identify_service(6379, "-ERR unknown command")
        assert svc == "redis"

    def test_ftp_banner(self):
        svc, ver = _identify_service(21, "220 ProFTPD 1.3.5 Server ready")
        assert svc == "ftp"

    def test_guess_by_port(self):
        assert _guess_by_port(22) == "ssh"
        assert _guess_by_port(80) == "http"
        assert _guess_by_port(3306) == "mysql"
        assert _guess_by_port(6379) == "redis"
        assert _guess_by_port(9999) is None

    def test_unknown_banner_falls_back_to_port(self):
        svc, ver = _identify_service(22, "SOME_UNKNOWN_BANNER")
        assert svc == "ssh"  # guessed from port


# ── ScanResult ─────────────────────────────────────────────────

class TestScanResult:
    def test_defaults(self):
        r = ScanResult(host="10.0.0.1", port=80)
        assert r.service is None
        assert r.probes == {}
        assert r.vulnerabilities == []

    def test_enriched(self):
        r = ScanResult(host="10.0.0.1", port=80, service="http",
                       version="2.4.49", probes={"http_tech": {"server": "Apache"}})
        assert r.service == "http"
        assert "http_tech" in r.probes


# ── VulnDatabase ───────────────────────────────────────────────

class TestVulnDatabase:
    @pytest.fixture
    def db(self):
        vdb = VulnDatabase()
        vdb.load()
        return vdb

    def test_loads_default_signatures(self, db):
        assert db.count >= 15

    def test_check_apache_vulnerable(self, db):
        vulns = db.check("apache", "2.4.49")
        assert len(vulns) >= 1
        cves = [v["cve"] for v in vulns]
        assert "CVE-2021-41773" in cves

    def test_check_apache_safe(self, db):
        vulns = db.check("apache", "2.4.51")
        assert len(vulns) == 0  # 2.4.51 is patched

    def test_check_apache_lower_bound(self, db):
        vulns = db.check("apache", "2.4.48")
        # 2.4.48 is < 2.4.49, should NOT match CVE-2021-41773
        cves = [v["cve"] for v in vulns]
        assert "CVE-2021-41773" not in cves

    def test_check_openssh_regresshion(self, db):
        vulns = db.check("openssh", "8.9p1")
        cves = [v["cve"] for v in vulns]
        assert "CVE-2024-6387" in cves

    def test_check_openssh_patched(self, db):
        vulns = db.check("openssh", "9.8p1")
        cves = [v["cve"] for v in vulns]
        assert "CVE-2024-6387" not in cves

    def test_check_eternalblue(self, db):
        vulns = db.check("smb", "any")
        cves = [v["cve"] for v in vulns]
        assert "CVE-2017-0144" in cves

    def test_check_log4shell(self, db):
        vulns = db.check("log4j", "2.14.1")
        cves = [v["cve"] for v in vulns]
        assert "CVE-2021-44228" in cves

    def test_check_log4j_patched(self, db):
        vulns = db.check("log4j", "2.15.0")
        assert len(vulns) == 0

    def test_check_unknown_service(self, db):
        vulns = db.check("unknown_service", "1.0")
        assert len(vulns) == 0

    def test_check_bulk(self, db):
        vulns = db.check_bulk([
            {"service": "apache", "version": "2.4.49", "port": 80},
            {"service": "openssh", "version": "8.9p1", "port": 22},
            {"service": "redis", "version": "7.0.5", "port": 6379},
        ])
        assert len(vulns) >= 2  # apache + openssh vulns
        assert any("80" in k for k in vulns)
        assert any("22" in k for k in vulns)

    def test_severity_filtering(self, db):
        vulns = db.check("apache", "2.4.49")
        severities = [v["severity"] for v in vulns]
        assert "critical" in severities or "high" in severities

    def test_exploit_module_reference(self, db):
        vulns = db.check("smb", "any")
        eternal = [v for v in vulns if v["cve"] == "CVE-2017-0144"]
        if eternal:
            assert eternal[0].get("exploit_module") == "eternalblue"

    def test_version_normalization_openssh(self, db):
        # "8.9p1" should normalize to "8.9.1"
        vulns = db.check("openssh", "8.9p1")
        assert len(vulns) >= 1


# ── ContextualScanEngine ──────────────────────────────────────

class TestContextualScanEngine:
    @pytest.fixture
    def engine(self):
        return ContextualScanEngine()

    def test_initialization(self, engine):
        assert engine.vuln_db is None
        assert engine.ai is None

    def test_with_vuln_db(self):
        vdb = VulnDatabase()
        engine = ContextualScanEngine(vuln_db=vdb)
        assert engine.vuln_db is vdb

    @pytest.mark.asyncio
    async def test_scan_localhost_closed(self, engine):
        # Localhost should have some open ports (at least from other tools)
        results = await engine.scan("127.0.0.1", ports=[9999, 9998], timeout=0.5)
        # These ports are likely closed → empty results
        assert isinstance(results, list)
