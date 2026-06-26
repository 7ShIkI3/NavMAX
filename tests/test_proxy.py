"""Tests du module Proxy NavMAX — Phase 2."""

import pytest


class TestInterceptor:
    def test_create_flow(self) -> None:
        from navmax.proxy import InterceptedFlow

        flow = InterceptedFlow(method="GET", host="example.com", path="/")
        assert flow.method == "GET"
        assert flow.host == "example.com"
        assert flow.status == "pending"

    def test_interceptor_default_off(self) -> None:
        from navmax.proxy import Interceptor

        i = Interceptor()
        assert not i.intercept_enabled

    def test_interceptor_toggle(self) -> None:
        from navmax.proxy import Interceptor

        i = Interceptor()
        i.intercept_enabled = True
        assert i.intercept_enabled
        i.intercept_enabled = False
        assert not i.intercept_enabled

    def test_flow_summary(self) -> None:
        from navmax.proxy import InterceptedFlow

        flow = InterceptedFlow(
            method="POST",
            host="target.com",
            port=443,
            path="/login",
            response_status=200,
        )
        summary = flow.summary()
        assert "POST" in summary
        assert "target.com" in summary
        assert "200" in summary


class TestRepeater:
    @pytest.mark.asyncio
    async def test_repeater_send(self) -> None:
        from navmax.proxy import Repeater

        r = Repeater()
        # httpbin peut rate-limiter → on accepte 200 ou 503
        result = await r.send("GET", "http://httpbin.org/get?test=1")
        assert result.status in (200, 503)
        assert result.elapsed_ms > 0
        await r.close()

    @pytest.mark.asyncio
    async def test_repeater_error(self) -> None:
        from navmax.proxy import Repeater

        r = Repeater()
        result = await r.send("GET", "http://nonexistent.invalid:9999/")
        assert result.status == 0
        assert result.error is not None
        await r.close()


class TestWebScanner:
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Test réseau flaky — httpbin.org parfois inaccessible")
    async def test_scan_headers(self) -> None:
        from navmax.proxy import WebScanner

        s = WebScanner(timeout=5.0)
        vulns = await s.scan_url("http://httpbin.org/status/200")
        # httpbin ne renvoie pas de headers de sécurité → au moins 1 vuln
        assert len(vulns) >= 1
        severities = [v.severity for v in vulns]
        assert "medium" in severities or "low" in severities
        await s.close()

    @pytest.mark.asyncio
    async def test_scan_no_xss_on_safe_page(self) -> None:
        from navmax.proxy import WebScanner

        s = WebScanner(timeout=5.0)
        vulns = await s.scan_url("http://httpbin.org/get?safe=1")
        xss_vulns = [v for v in vulns if "XSS reflété" in v.name]
        assert len(xss_vulns) == 0
        await s.close()


class TestFuzzer:
    @pytest.mark.asyncio
    async def test_fuzzer_baseline(self) -> None:
        from navmax.proxy import Fuzzer

        f = Fuzzer(concurrency=3, categories=["xss", "sqli"])
        report = await f.fuzz_url("http://httpbin.org/get?q=hello")
        # httpbin reflète les paramètres (normal) → on teste juste que le fuzzer tourne sans crash
        assert report.total_tests > 0
        assert report.duration_ms > 0
        await f.close()

    @pytest.mark.asyncio
    async def test_fuzzer_custom_categories(self) -> None:
        from navmax.proxy import Fuzzer

        f = Fuzzer(concurrency=2, categories=["overflow"])
        report = await f.fuzz_url("http://httpbin.org/get?q=test")
        assert report.total_tests > 0
        await f.close()


class TestCerts:
    def test_generate_ca(self) -> None:
        from navmax.proxy.certs import load_or_generate_ca

        ca_cert, ca_key = load_or_generate_ca()
        assert ca_cert is not None
        assert ca_key is not None

    def test_generate_host_cert(self) -> None:
        from navmax.proxy.certs import generate_host_cert

        cert_pem, key_pem = generate_host_cert("test.example.com")
        assert "BEGIN CERTIFICATE" in cert_pem
        assert "BEGIN PRIVATE KEY" in key_pem


class TestFlowActions:
    def test_flow_actions(self) -> None:
        from navmax.proxy import FlowAction, FlowStatus

        assert FlowAction.FORWARD == "forward"
        assert FlowAction.DROP == "drop"
        assert FlowAction.MODIFY == "modify"
        assert FlowStatus.PENDING == "pending"
        assert FlowStatus.FORWARDED == "forwarded"
