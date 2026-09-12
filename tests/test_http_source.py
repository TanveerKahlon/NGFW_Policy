import httpx
import respx

from src.core.config import SourceConfig
from src.sources.base import FetchStatus
from src.sources.http_source import HttpSource


def make_source(**kwargs) -> HttpSource:
    return HttpSource(SourceConfig(name="t", **kwargs), user_agent="test-agent/1.0")


@respx.mock
async def test_successful_fetch_populates_result():
    respx.get("https://example.com/a").mock(
        return_value=httpx.Response(200, html="<h1>Advisory</h1>")
    )
    source = make_source(url="https://example.com/a")
    try:
        result = await source.fetch("https://example.com/a")
    finally:
        await source.close()

    assert result.ok
    assert result.status_code == 200
    assert "Advisory" in result.html
    assert result.url_canonical == "https://example.com/a"


@respx.mock
async def test_404_marks_failed():
    respx.get("https://example.com/missing").mock(return_value=httpx.Response(404))
    source = make_source()
    try:
        result = await source.fetch("https://example.com/missing")
    finally:
        await source.close()

    assert result.status is FetchStatus.FAILED
    assert result.error == "HTTP 404"


@respx.mock
async def test_429_marks_rate_limited():
    respx.get("https://example.com/x").mock(return_value=httpx.Response(429))
    source = make_source()
    try:
        result = await source.fetch("https://example.com/x")
    finally:
        await source.close()
    assert result.status is FetchStatus.RATE_LIMITED


@respx.mock
async def test_network_error_is_captured_not_raised():
    respx.get("https://example.com/boom").mock(side_effect=httpx.ConnectError("refused"))
    source = make_source()
    try:
        result = await source.fetch("https://example.com/boom")
    finally:
        await source.close()

    assert result.status is FetchStatus.FAILED
    assert "refused" in result.error


@respx.mock
async def test_configured_user_agent_is_sent():
    route = respx.get("https://example.com/ua").mock(return_value=httpx.Response(200, text="ok"))
    source = HttpSource(
        SourceConfig(name="t", headers={"User-Agent": "custom/9"}), user_agent="ignored"
    )
    try:
        await source.fetch("https://example.com/ua")
    finally:
        await source.close()

    assert route.calls[0].request.headers["user-agent"] == "custom/9"


@respx.mock
async def test_403_without_impersonate_does_not_retry():
    route = respx.get("https://example.com/blocked").mock(return_value=httpx.Response(403))
    source = make_source()
    try:
        result = await source.fetch("https://example.com/blocked")
    finally:
        await source.close()

    assert route.call_count == 1
    assert result.status is FetchStatus.FAILED
