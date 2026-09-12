import asyncio
import time

from src.utils.rate_limiter import RateLimiter


async def test_first_request_is_immediate():
    limiter = RateLimiter(default_rps=1.0)
    assert await limiter.acquire("https://example.com/a") == 0.0


async def test_second_request_to_same_domain_waits():
    limiter = RateLimiter(default_rps=20.0)
    await limiter.acquire("https://example.com/a")
    start = time.monotonic()
    await limiter.acquire("https://example.com/b")
    assert time.monotonic() - start >= 0.03


async def test_domains_are_independent():
    limiter = RateLimiter(default_rps=2.0)
    await limiter.acquire("https://a.com/1")
    start = time.monotonic()
    await limiter.acquire("https://b.com/1")
    assert time.monotonic() - start < 0.05


async def test_per_domain_override_applies():
    limiter = RateLimiter(default_rps=0.1)
    limiter.set_domain_rps("fast.com", 100.0)
    await limiter.acquire("https://fast.com/1")
    start = time.monotonic()
    await limiter.acquire("https://fast.com/2")
    assert time.monotonic() - start < 0.1


async def test_concurrent_acquires_serialize():
    limiter = RateLimiter(default_rps=50.0)
    start = time.monotonic()
    await asyncio.gather(*(limiter.acquire("https://example.com/x") for _ in range(3)))
    assert time.monotonic() - start >= 0.04
