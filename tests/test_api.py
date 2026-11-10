import json
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"


def test_scan_missing_body(client):
    res = client.post("/api/scan", data="invalid json", content_type="application/json")
    assert res.status_code == 400


def test_scan_empty_url(client):
    res = client.post("/api/scan", json={"url": "   "})
    assert res.status_code == 400


def test_scan_private_ip_ssrf(client):
    res = client.post("/api/scan", json={"url": "http://127.0.0.1:8080/admin"})
    assert res.status_code == 200
    data = res.get_json()
    assert "scan_id" in data
    assert "scanned_at" in data
    assert data["submitted_url"] == "http://127.0.0.1:8080/admin"
    assert "SSRF Protection Blocked" in data["fetch_status"]
    signal_ids = [s["id"] for s in data["signals"]]
    assert "SEC_SSRF_PROHIBITED" in signal_ids
    assert data["score"] > 0
    assert "limitations" in data
    assert any("Heuristic result" in lim for lim in data["limitations"])


def test_scan_phishing_heuristics(client):
    # Lexical triggers: long URL, @ symbol, brand spoofing
    phish_url = "http://account-update@paypal-security-verification.top/signin/index.php?" + ("token=" + "a" * 80)
    res = client.post("/api/scan", json={"url": phish_url})
    assert res.status_code == 200
    data = res.get_json()
    assert data["score"] >= 70
    assert data["risk_band"] in ("Suspicious", "High Risk")
    signal_ids = [s["id"] for s in data["signals"]]
    assert "LEX_LONG_URL" in signal_ids
    assert "LEX_AT_SYMBOL" in signal_ids
    assert "LEX_BRAND_SPOOFING" in signal_ids


def test_history_endpoint(client):
    # Perform a scan first
    client.post("/api/scan", json={"url": "https://example.com/test-history"})
    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.get_json()
    assert "scans" in data
    assert data["count"] >= 1
    recent = data["scans"][0]
    assert "scan_id" in recent
    assert "score" in recent
    assert "risk_band" in recent
