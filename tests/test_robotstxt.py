import asyncio

import httpx
import respx

from src.utils.robotstxt import RobotsTxtChecker

ROBOTS = "User-agent: *\nDisallow: /private\nCrawl-delay: 2\n"


@respx.mock
async def test_allow_and_disallow():
    respx.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text=ROBOTS)
    )
    checker = RobotsTxtChecker(user_agent="test")
    assert await checker.can_fetch("https://example.com/public")
    assert not await checker.can_fetch("https://example.com/private/x")


@respx.mock
async def test_concurrent_checks_fetch_robots_once():
    """The per-origin lock prevents a thundering herd on the same host."""
    route = respx.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text=ROBOTS)
    )
    checker = RobotsTxtChecker(user_agent="test")
    await asyncio.gather(*(checker.can_fetch(f"https://example.com/p{i}") for i in range(8)))
    assert route.call_count == 1


@respx.mock
async def test_separate_origins_fetch_separately():
    a = respx.get("https://a.com/robots.txt").mock(return_value=httpx.Response(200, text=ROBOTS))
    b = respx.get("https://b.com/robots.txt").mock(return_value=httpx.Response(200, text=ROBOTS))
    checker = RobotsTxtChecker(user_agent="test")
    await asyncio.gather(checker.can_fetch("https://a.com/x"), checker.can_fetch("https://b.com/x"))
    assert a.call_count == 1 and b.call_count == 1


@respx.mock
async def test_missing_robots_allows_everything():
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    checker = RobotsTxtChecker(user_agent="test")
    assert await checker.can_fetch("https://example.com/anything")


@respx.mock
async def test_network_failure_fails_open():
    respx.get("https://example.com/robots.txt").mock(side_effect=httpx.ConnectError("down"))
    checker = RobotsTxtChecker(user_agent="test")
    assert await checker.can_fetch("https://example.com/anything")


@respx.mock
async def test_crawl_delay_reuses_cached_parser():
    route = respx.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text=ROBOTS)
    )
    checker = RobotsTxtChecker(user_agent="test")
    await checker.can_fetch("https://example.com/x")
    assert await checker.crawl_delay("https://example.com/x") == 2.0
    assert route.call_count == 1
