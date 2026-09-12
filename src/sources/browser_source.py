"""Playwright source for pages that only exist after JavaScript runs."""
from __future__ import annotations

from typing import Any

from src.core.config import SourceConfig
from src.sources.base import BaseSource, FetchResult, FetchStatus
from src.utils.logging import get_logger
from src.utils.url import canonicalize

logger = get_logger(__name__)


class BrowserSource(BaseSource):
    """Renders each URL in headless Chromium and returns the settled DOM.

    Requires the `browser` extra: pip install -e '.[browser]'
    The Chromium build is already cached under ~/Library/Caches/ms-playwright.
    """

    kind = "browser"

    def __init__(self, config: SourceConfig, timeout: float = 30.0, user_agent: str = ""):
        super().__init__(config)
        self.timeout = timeout
        self._default_ua = user_agent
        self._playwright = None
        self._browser = None

    async def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            raise RuntimeError(
                "playwright is not installed. Run: pip install -e '.[browser]'"
            ) from e

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        return self._browser

    async def fetch(self, url: str, **kwargs: Any) -> FetchResult:
        result = FetchResult(
            source_name=self.name,
            url_original=url,
            url_canonical=canonicalize(url),
        )
        context = None
        try:
            browser = await self._ensure_browser()
            context = await browser.new_context(
                user_agent=self._default_ua or None,
                extra_http_headers=self.config.headers or None,
            )
            page = await context.new_page()
            response = await page.goto(
                url, timeout=self.timeout * 1000, wait_until="domcontentloaded"
            )
            await page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)

            result.html = await page.content()
            result.url_final = page.url
            if response is not None:
                result.status_code = response.status
                result.headers = dict(response.headers)
            result.status = FetchStatus.SUCCESS if result.html else FetchStatus.FAILED
        except Exception as e:
            result.status = FetchStatus.FAILED
            result.error = str(e)
            logger.warning("browser_fetch_failed", url=url, error=str(e))
        finally:
            if context is not None:
                await context.close()
        return result

    async def close(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None
