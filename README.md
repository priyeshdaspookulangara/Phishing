# Real-Time Phishing Website & URL Heuristic Analyzer

A high-performance heuristic analyzer prototype and single-page dashboard designed to detect phishing websites and malicious URLs in real time.

---

## 1. Architecture & Design

The system implements a defense-in-depth inspection pipeline partitioned into distinct, modular subsystems:

- **Module A: Lexical URL Analysis (`analyzer/lexical.py`)**
  - Parses URLs using `urllib.parse`, `ipaddress`, and regular expressions.
  - Identifies long URLs (>75 characters).
  - Detects raw IP address hostnames (both IPv4 and IPv6).
  - Detects embedded `@` credential delimiter spoofing.
  - Computes subdomain hierarchy depth (>3 levels).
  - Flags abnormal special characters and multiple consecutive hyphens.
  - Detects target brand keyword spoofing (PayPal, Apple, Google, Chase, etc.) in non-official domains and paths.
  - Flags high-risk top-level domains (TLDs like `.top`, `.xyz`, `.icu`).

- **Module B: Restricted HTTP Client & DOM Inspector (`analyzer/dom.py`)**
  - **Strict SSRF Mitigation:**
    - Scheme validation (restricting solely to HTTP/HTTPS).
    - Pre-flight DNS resolution checking all resolved IPs against private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local/cloud metadata (`169.254.169.254`), multicast, and reserved ranges.
    - Disables automatic HTTP redirects to avoid redirect-based SSRF bypasses.
    - Strictly bounds network timeouts (3.5s) and maximum response payload size (1MB).
  - **DOM & Transport Inspection:**
    - Identifies unencrypted plain HTTP transport.
    - Identifies sensitive credential (password) inputs served over unencrypted HTTP.
    - Scans for form action mismatches (submitting credentials or user data to external or untrusted domains).
    - Detects excessive hidden input fields (`>3`), characteristic of phishing kits carrying stolen metadata.
    - Flags external iframe embeds used for phishing overlays.

- **Module C: Scoring & Risk Classification (`analyzer/scoring.py`)**
  - Aggregates weighted feature flags with point values.
  - Clamps composite score into a 0–100 scale.
  - Maps score to risk bands:
    - **Lower risk:** 0 – 30%
    - **Suspicious:** 31 – 70%
    - **High Risk:** 71 – 100%

- **Persistence Layer (`analyzer/db.py`)**
  - SQLite3 database storing `scan_id`, `scanned_at`, `submitted_url`, `score`, `risk_band`, `fetch_status`, `signals_json`, and `limitations_json`.
  - Indexed for fast retrieval of historical scans.

- **Cybersecurity Dark Glassmorphism Frontend (`templates/index.html`, `static/style.css`, `static/app.js`)**
  - Responsive single-page application built with HTML5, CSS3, and Vanilla JavaScript.
  - High-contrast typography, cyber cyan accents, dynamic risk gauge, and evidence breakdown with signal tags (`URL`, `DOM`, `Safety`).
  - Scan history table with instant reload and inspection detail modal/card.
  - Prominent disclaimer: *"Heuristic result; not a guarantee. Results should support, not replace, human review."*

---

## 2. API Endpoints

### `POST /api/scan`
- **Request Body:**
  ```json
  {
    "url": "https://example.com/login"
  }
  ```
- **Response Format:**
  ```json
  {
    "scan_id": "c1f7ef69-8db8-40da-bb96-6e4dd38b0e51",
    "scanned_at": "2026-11-10T02:10:00.000000+00:00",
    "submitted_url": "https://example.com/login",
    "fetch_status": "Fetched successfully",
    "score": 0,
    "risk_band": "Lower risk",
    "signals": [],
    "limitations": [
      "Heuristic result; not a guarantee. Results should support, not replace, human review.",
      "Dynamic client-side execution (e.g. JavaScript obfuscation, CAPTCHAs, geofencing) may evade static DOM checks.",
      "SSRF defense policies intentionally restrict private IP ranges, cloud metadata endpoints, and non-HTTP protocols."
    ]
  }
  ```

### `GET /api/history?limit=50`
- Returns a list of past scans ordered by newest first.

### `GET /api/health`
- Service health status check.

---

## 3. Local Setup & Execution Instructions

### Prerequisites
- Python 3.10+
- `pip`

### Installation
```bash
# Clone the repository and navigate into the root directory
cd <repo_directory>

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# Start the Flask web server
python3 app.py
```
By default, the server listens at `http://0.0.0.0:5000`. Navigate to `http://localhost:5000` in your web browser.

### Running Automated Tests
```bash
PYTHONPATH=. pytest -v
```
