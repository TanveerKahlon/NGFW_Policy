"""Plain HTTP source: httpx first, curl_cffi fallback for TLS-fingerprint walls."""
from __future__ import annotations

from typing import Any

import httpx

from src.core.config import SourceConfig
from src.sources.base import BaseSource, FetchResult, FetchStatus
from src.utils.logging import get_logger
from src.utils.url import canonicalize

logger = get_logger(__name__)

# Status codes worth retrying through the impersonating client.
BLOCK_CODES = {403, 429, 503}


class HttpSource(BaseSource):
    """Fetches HTML over HTTP.

    When a request is blocked with 403/429/503 and the source config sets
    `impersonate`, the fetch is retried with curl_cffi using a real browser's
    TLS/JA3 fingerprint. That fallback is optional: without curl_cffi installed
    the original response is returned unchanged.
    """

    kind = "http"

    def __init__(self, config: SourceConfig, timeout: float = 30.0, user_agent: str = ""):
        super().__init__(config)
        self.timeout = timeout
        self._default_ua = user_agent
        self._client: httpx.AsyncClient | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": self._default_ua or "ngfw-crawler/0.1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        headers.update(self.config.headers)
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                headers=self._headers(),
            )
        return self._client

    async def fetch(self, url: str, **kwargs: Any) -> FetchResult:
        result = FetchResult(
            source_name=self.name,
            url_original=url,
            url_canonical=canonicalize(url),
        )
        try:
            client = await self._get_client()
            resp = await client.get(url)
            result.status_code = resp.status_code
            result.url_final = str(resp.url)
            result.headers = dict(resp.headers)

            if resp.status_code in BLOCK_CODES and self.config.impersonate:
                logger.info("http_blocked_retrying_impersonated",
                            url=url, code=resp.status_code, profile=self.config.impersonate)
                impersonated = await self._fetch_impersonated(url)
                if impersonated is not None:
                    return impersonated

            if resp.status_code >= 400:
                result.status = (
                    FetchStatus.RATE_LIMITED if resp.status_code == 429 else FetchStatus.FAILED
                )
                result.error = f"HTTP {resp.status_code}"
                return result

            result.html = resp.text
            result.status = FetchStatus.SUCCESS
        except Exception as e:
            result.status = FetchStatus.FAILED
            result.error = str(e)
            logger.warning("http_fetch_failed", url=url, error=str(e))
        return result

    async def _fetch_impersonated(self, url: str) -> FetchResult | None:
        """Retry via curl_cffi. Returns None if curl_cffi is unavailable."""
        try:
            from curl_cffi.requests import AsyncSession
        except ImportError:
            logger.debug("curl_cffi_unavailable")
            return None

        result = FetchResult(
            source_name=self.name,
            url_original=url,
            url_canonical=canonicalize(url),
        )
        try:
            async with AsyncSession() as session:
                resp = await session.get(
                    url,
                    headers=self._headers(),
                    impersonate=self.config.impersonate,
                    timeout=self.timeout,
                )
            result.status_code = resp.status_code
            result.url_final = str(resp.url)
            result.headers = dict(resp.headers)
            result.metadata["impersonated"] = self.config.impersonate
            if resp.status_code >= 400:
                result.status = FetchStatus.FAILED
                result.error = f"HTTP {resp.status_code} (impersonated)"
            else:
                result.html = resp.text
                result.status = FetchStatus.SUCCESS
        except Exception as e:
            result.status = FetchStatus.FAILED
            result.error = f"impersonated fetch failed: {e}"
        return result

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
