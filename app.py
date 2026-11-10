"""Flask Application Entrypoint for Real-Time Phishing Website & URL Heuristic Analyzer.

Endpoints:
- POST /api/scan: Accepts JSON {"url": "..."}, executes lexical & SSRF-safe DOM inspection, returns risk score.
- GET /api/history: Returns history of past scans.
- GET /: Serves single-page web dashboard application.
- GET /api/health: Service status endpoint.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Any
import uuid

from flask import Flask, jsonify, render_template, request

from analyzer.db import get_recent_scans, init_db, save_scan
from analyzer.dom import SSRFValidationError, analyze_dom, safe_fetch_html, validate_url_for_ssrf
from analyzer.lexical import analyze_lexical
from analyzer.scoring import compute_risk_score

app = Flask(__name__, static_folder="static", template_folder="templates")
DB_PATH = os.environ.get("PHISH_DB_PATH", os.path.join(os.path.dirname(__file__), "analyzer", "scans.db"))

# Ensure DB is initialized
init_db(DB_PATH)

DEFAULT_LIMITATIONS: list[str] = [
    "Heuristic result; not a guarantee. Results should support, not replace, human review.",
    "Dynamic client-side execution (e.g. JavaScript obfuscation, CAPTCHAs, geofencing) may evade static DOM checks.",
    "SSRF defense policies intentionally restrict private IP ranges, cloud metadata endpoints, and non-HTTP protocols.",
]


@app.route("/")
def index():
    """Serve the single-page dashboard application."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/scan", methods=["POST"])
def scan_url():
    """Analyze a submitted URL using Module A (Lexical) and Module B (DOM Inspection).

    JSON Payload:
        { "url": "https://example.com" }

    Returns structured JSON:
        scan_id, scanned_at, submitted_url, fetch_status, score, risk_band, signals, limitations
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload. Expected {'url': 'http://...'}"}), 400

    raw_url = data.get("url")
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({"error": "Field 'url' is required and must be a non-empty string."}), 400

    raw_url = raw_url.strip()
    scan_id = str(uuid.uuid4())
    scanned_at = datetime.now(timezone.utc).isoformat()

    all_signals: list[dict[str, Any]] = []
    limitations: list[str] = list(DEFAULT_LIMITATIONS)

    # 1. Module A: Lexical Analysis
    lexical_result = analyze_lexical(raw_url)
    all_signals.extend(lexical_result.get("signals", []))
    normalized_url = lexical_result.get("normalized_url", raw_url)

    # 2. Module B: DOM Inspection (Conditionally and safely run if URL passes SSRF checks)
    fetch_status = "Skipped"
    html_content = None

    # Check if safe for SSRF before attempting fetch
    try:
        validate_url_for_ssrf(normalized_url)
        # SSRF checks passed -> safe to fetch
        html_content, fetch_status, http_code = safe_fetch_html(normalized_url)
        if html_content is not None:
            dom_signals = analyze_dom(normalized_url, html_content, lexical_result.get("parsed", {}).get("hostname"))
            all_signals.extend(dom_signals)
        else:
            limitations.append(f"DOM inspection partial: {fetch_status}")
    except SSRFValidationError as ssrf_err:
        fetch_status = f"SSRF Protection Blocked: {ssrf_err}"
        # Trigger an SSRF threat signal
        all_signals.append(
            {
                "id": "SEC_SSRF_PROHIBITED",
                "source": "Safety Engine",
                "name": "SSRF / Restricted Target Blocked",
                "description": f"Target was blocked by safety policy: {ssrf_err}",
                "points": 35,
            }
        )
        limitations.append("DOM inspection was aborted due to safety constraints (private or reserved address).")
    except Exception as exc:
        fetch_status = f"Fetch failed: {exc}"
        limitations.append(f"DOM inspection unavailable: {exc}")

    # 3. Module C: Scoring & Classification
    scoring_result = compute_risk_score(all_signals)
    score = scoring_result["score"]
    risk_band = scoring_result["risk_band"]
    final_signals = scoring_result["signals"]

    # 4. Persistence: Save to SQLite
    try:
        save_scan(
            scan_id=scan_id,
            scanned_at=scanned_at,
            submitted_url=raw_url,
            score=score,
            risk_band=risk_band,
            fetch_status=fetch_status,
            signals=final_signals,
            limitations=limitations,
            db_path=DB_PATH,
        )
    except Exception as db_err:
        app.logger.error(f"Failed to save scan to database: {db_err}")

    response_payload = {
        "scan_id": scan_id,
        "scanned_at": scanned_at,
        "submitted_url": raw_url,
        "fetch_status": fetch_status,
        "score": score,
        "risk_band": risk_band,
        "signals": final_signals,
        "limitations": limitations,
    }

    return jsonify(response_payload), 200


@app.route("/api/history", methods=["GET"])
def history():
    """Retrieve list of previous scan summaries from SQLite database."""
    try:
        limit = int(request.args.get("limit", 50))
    except (ValueError, TypeError):
        limit = 50

    try:
        scans = get_recent_scans(limit=limit, db_path=DB_PATH)
        return jsonify({"scans": scans, "count": len(scans)}), 200
    except Exception as exc:
        return jsonify({"error": f"Failed to retrieve history: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
