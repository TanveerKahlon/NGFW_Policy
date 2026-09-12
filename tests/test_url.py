from src.utils.url import canonicalize, is_fetchable


def test_canonicalize_strips_fragment_and_tracking():
    url = "HTTPS://Example.COM:443/Advisory/?utm_source=rss&id=7#section-2"
    assert canonicalize(url) == "https://example.com/Advisory?id=7"


def test_canonicalize_keeps_non_default_port():
    assert canonicalize("http://example.com:8080/a") == "http://example.com:8080/a"


def test_canonicalize_root_slash_preserved():
    assert canonicalize("https://example.com/") == "https://example.com/"
    assert canonicalize("https://example.com/a/") == "https://example.com/a"


def test_canonicalize_is_stable():
    a = canonicalize("https://example.com/x?b=2&a=1")
    assert canonicalize(a) == a


def test_is_fetchable_rejects_non_http():
    assert is_fetchable("https://example.com/a")
    assert not is_fetchable("ftp://example.com/a")
    assert not is_fetchable("javascript:alert(1)")
    assert not is_fetchable("mailto:a@b.com")
    assert not is_fetchable("https:///nohost")
