from analyzer.lexical import analyze_lexical, is_ip_address


def test_is_ip_address():
    assert is_ip_address("192.168.1.1")
    assert is_ip_address("8.8.8.8")
    assert is_ip_address("2001:db8::1")
    assert is_ip_address("[2001:db8::1]")
    assert not is_ip_address("example.com")
    assert not is_ip_address("paypal-security.com")


def test_lexical_long_url():
    long_url = "http://example.com/" + "a" * 80
    res = analyze_lexical(long_url)
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_LONG_URL" in signal_ids


def test_lexical_ip_host():
    res = analyze_lexical("http://192.0.2.1/login")
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_IP_HOST" in signal_ids


def test_lexical_at_symbol():
    res = analyze_lexical("http://legit.com@evil-site.com/login")
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_AT_SYMBOL" in signal_ids


def test_lexical_deep_subdomains():
    res = analyze_lexical("http://a.b.c.d.example.com/test")
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_DEEP_SUBDOMAINS" in signal_ids


def test_lexical_multiple_hyphens():
    res = analyze_lexical("http://secure-update-login.com/")
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_MULTIPLE_HYPHENS" in signal_ids


def test_lexical_brand_spoofing():
    res = analyze_lexical("http://paypal-verification-alert.com/login")
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_BRAND_SPOOFING" in signal_ids


def test_lexical_legit_brand():
    res = analyze_lexical("https://www.paypal.com/signin")
    signal_ids = [s["id"] for s in res["signals"]]
    assert "LEX_BRAND_SPOOFING" not in signal_ids
