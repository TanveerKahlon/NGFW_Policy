from src.extractors.indicator_extractor import IndicatorExtractor, refang


def extract(text: str) -> dict:
    return IndicatorExtractor().extract("", text=text)


def test_refang_common_forms():
    assert refang("evil[.]com") == "evil.com"
    assert refang("hxxps://bad[.]net/x") == "https://bad.net/x"


def test_cve_and_cvss():
    data = extract("Tracked as cve-2024-3400 with CVSS 10.0 severity.")
    assert data["cves"] == ["CVE-2024-3400"]
    assert data["cvss_max"] == 10.0


def test_ipv4_and_cidr_split():
    data = extract("C2 at 45.77.12.9 and blocklist 10.0.0.0/8")
    assert data["ipv4"] == ["45.77.12.9"]
    assert data["cidrs"] == ["10.0.0.0/8"]


def test_invalid_octets_rejected():
    """Version strings must not be mistaken for addresses."""
    data = extract("PAN-OS 11.1.999.1 and 999.1.1.1 are not addresses")
    assert data["ipv4"] == []


def test_defanged_indicators_recovered():
    data = extract("beacon to 185[.]220[.]101[.]5 via hxxp://evil[.]top/gate")
    assert "185.220.101.5" in data["ipv4"]
    assert "evil.top" in data["domains"]


def test_hash_types_do_not_overlap():
    sha256 = "e" * 64
    md5 = "a" * 32
    data = extract(f"hashes: {sha256} {md5}")
    assert data["sha256"] == [sha256]
    assert data["md5"] == [md5]
    assert sha256 not in data["sha1"]


def test_noise_domains_filtered():
    data = extract("See https://nvd.nist.gov/vuln and evil.xyz")
    assert "nvd.nist.gov" not in data["domains"]
    assert "evil.xyz" in data["domains"]


def test_results_are_sorted_and_deduped():
    data = extract("1.1.1.1 1.1.1.1 8.8.8.8")
    assert data["ipv4"] == ["1.1.1.1", "8.8.8.8"]


# --- CVSS phrasings taken verbatim from live advisories ---

def test_cvss_vector_version_is_not_a_score():
    """CVSS:4.0/... is the spec version; the score is 4.8."""
    text = "LOWCVSS-B: 4.8 (CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N)"
    assert extract(text)["cvss_max"] == 4.8


def test_cvss_cisa_table_format():
    text = "| CVSS | Vendor | Equipment | Vulnerabilities |\n|---|---|---|---|\n| v3 8.4 | AVEVA |"
    assert extract(text)["cvss_max"] == 8.4


def test_cvss_base_score_prose():
    assert extract("has a CVSS v3.1 base score of 9.8, critical")["cvss_max"] == 9.8


def test_cvss_takes_the_maximum():
    text = "CVSS-B: 2.4 (CVSS:4.0/AV:A/AC:L) and elsewhere CVSS-B: 7.5 (CVSS:4.0/AV:N/AC:L)"
    assert extract(text)["cvss_max"] == 7.5


def test_cvss_absent_when_only_a_vector_is_present():
    assert extract("Vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N")["cvss_max"] is None


def test_no_cvss_mention_yields_none():
    assert extract("Just an advisory about CVE-2024-3400.")["cvss_max"] is None
