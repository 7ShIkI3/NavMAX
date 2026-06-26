"""Tests pour le Playwright Spider (SPA crawler).

Note: Playwright n'est pas installé dans l'environnement de test.
Tous les tests mockent l'import ou utilisent le fallback.
"""

import pytest

from navmax.proxy.playwright_spider import (
    PlaywrightNotAvailableError,
    PlaywrightSpider,
    SPACrawlResult,
    SPAEndpoint,
    crawl_with_fallback,
)

# ── Tests dataclasses ────────────────────────────────────────────


class TestSPAEndpoint:
    """SPAEndpoint dataclass."""

    def test_defaults(self) -> None:
        ep = SPAEndpoint(url="http://example.com")
        assert ep.url == "http://example.com"
        assert ep.method == "GET"
        assert ep.params == []
        assert ep.source == ""

    def test_full_init(self) -> None:
        ep = SPAEndpoint(
            url="http://example.com/api/login",
            method="POST",
            params=["username", "password"],
            source="fetch",
            status_code=200,
            content_type="application/json",
        )
        assert ep.method == "POST"
        assert "username" in ep.params
        assert ep.source == "fetch"
        assert ep.status_code == 200


class TestSPACrawlResult:
    """SPACrawlResult dataclass."""

    def test_defaults(self) -> None:
        result = SPACrawlResult(
            base_url="http://example.com",
            visited_pages=0,
            discovered_endpoints=[],
            javascript_errors=[],
            console_logs=[],
            api_calls_captured=0,
            websocket_endpoints=[],
            duration_ms=0,
        )
        assert result.base_url == "http://example.com"
        assert result.visited_pages == 0
        assert result.api_calls_captured == 0

    def test_with_endpoints(self) -> None:
        endpoints = [
            SPAEndpoint(url="http://example.com/api/users"),
            SPAEndpoint(url="http://example.com/api/login", method="POST"),
        ]
        result = SPACrawlResult(
            base_url="http://example.com",
            visited_pages=3,
            discovered_endpoints=endpoints,
            javascript_errors=[{"url": "/", "message": "ReferenceError"}],
            console_logs=[{"url": "/", "level": "log", "text": "hello"}],
            api_calls_captured=2,
            websocket_endpoints=[],
            duration_ms=1500,
        )
        assert len(result.discovered_endpoints) == 2
        assert result.visited_pages == 3
        assert len(result.javascript_errors) == 1


# ── Tests PlaywrightSpider ───────────────────────────────────────


class TestPlaywrightSpider:
    """PlaywrightSpider — tests sans Playwright installé."""

    def test_init_defaults(self) -> None:
        spider = PlaywrightSpider()
        assert spider.headless is True
        assert spider.timeout == 30000
        assert spider.max_concurrent == 3

    def test_check_playwright_unavailable(self) -> None:
        spider = PlaywrightSpider()
        # Sans Playwright installé, doit retourner False
        available = spider._check_playwright()
        assert available is False

    def test_cache_check_result(self) -> None:
        spider = PlaywrightSpider()
        spider._check_playwright()
        assert spider._checked is True
        # Deuxième appel doit utiliser le cache
        assert spider._check_playwright() is False

    @pytest.mark.asyncio
    async def test_crawl_without_playwright_raises(self) -> None:
        spider = PlaywrightSpider()
        with pytest.raises(PlaywrightNotAvailableError):
            await spider.crawl("http://example.com", max_depth=1)


class TestPlaywrightNotAvailableError:
    """Exception quand Playwright est absent."""

    def test_error_message(self) -> None:
        err = PlaywrightNotAvailableError()
        assert "Playwright" in str(err)

    def test_custom_message(self) -> None:
        err = PlaywrightNotAvailableError("Pas de Chromium")
        assert "Pas de Chromium" in str(err)


# ── Tests fallback ───────────────────────────────────────────────


class TestFallback:
    """crawl_with_fallback quand Playwright absent."""

    @pytest.mark.asyncio
    async def test_fallback_returns_none(self) -> None:
        """Quand Playwright n'est pas installé, doit retourner None."""
        result = await crawl_with_fallback("http://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_prefer_spa_flag_accepted(self) -> None:
        """Le flag prefer_spa est accepté même sans Playwright."""
        result = await crawl_with_fallback("http://example.com", prefer_spa=True)
        assert result is None


# ── Intégration avec proxy/__init__.py ───────────────────────────


class TestModuleExport:
    """Vérifie que le module est importable depuis navmax.proxy."""

    def test_import_from_proxy(self) -> None:
        from navmax.proxy import playwright_spider

        assert hasattr(playwright_spider, "PlaywrightSpider")
        assert hasattr(playwright_spider, "crawl_with_fallback")
