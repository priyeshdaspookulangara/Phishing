"""Module B: Restricted HTTP Client with SSRF protections and DOM Inspection.

Protections:
- Resolve hostname before fetching to detect private, loopback, link-local, multicast, or reserved IPs.
- Block non-HTTP/HTTPS schemes (e.g. file://, gopher://, ftp://).
- Disable redirects or validate redirect destinations to prevent redirect SSRF attacks.
- Enforce strict connect/read timeouts (default 3 seconds).
- Enforce maximum download size (e.g. 1MB) to prevent memory exhaustion / zip bombs.

DOM Inspection:
- Form action mismatches: form action points to an external or untrusted domain or plain HTTP while page is HTTPS.
- Hidden input counts: elevated number of hidden form fields (>3) often used in phishing kits to carry stolen state or tokens.
- Transport indicators: non-SSL/plain HTTP transport, or password input fields served or submitted over unencrypted HTTP.
- Password input fields present on page.
- External iframe embeds / fake overlays.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import requests

# Maximum allowed HTML body size in bytes (1 MB)
MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_TIMEOUT = 3.5  # seconds


class SSRFValidationError(Exception):
    """Raised when target URL violates SSRF safety constraints."""
    pass


def validate_url_for_ssrf(url: str) -> tuple[str, str, int]:
    """Validate that the URL is safe to fetch and not pointing to internal/private targets.

    Returns:
        tuple (scheme, hostname, port)
    Raises:
        SSRFValidationError if URL is unsafe
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFValidationError(f"Invalid or unsupported scheme '{scheme}'. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL contains no valid hostname.")

    port = parsed.port or (443 if scheme == "https" else 80)

    # Check if host is direct IP
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            raise SSRFValidationError(f"Target IP address '{hostname}' is within a private, loopback, or reserved range.")
        return (scheme, hostname, port)
    except ValueError:
        # Not a raw IP literal; proceed to DNS resolution
        pass

    # Resolve hostname via DNS
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFValidationError(f"Failed to resolve hostname '{hostname}': {exc}")

    if not addr_info:
        raise SSRFValidationError(f"Could not resolve any IP address for host '{hostname}'.")

    for item in addr_info:
        sockaddr = item[4]
        resolved_ip = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            ):
                raise SSRFValidationError(
                    f"Resolved IP '{resolved_ip}' for host '{hostname}' is within a private, loopback, or reserved range."
                )
        except ValueError:
            raise SSRFValidationError(f"Invalid resolved IP '{resolved_ip}'.")

    return (scheme, hostname, port)


def safe_fetch_html(url: str) -> tuple[str | None, str, int | None]:
    """Safely fetch HTML content of target URL with SSRF protection, timeouts, and max body size.

    Returns:
        tuple (html_text or None, status_summary, http_status_code or None)
    """
    try:
        validate_url_for_ssrf(url)
    except SSRFValidationError as e:
        return None, f"Blocked by SSRF policy: {e}", None

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36 (HeuristicAnalyzer/1.0)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        # Stream response so we can enforce byte limits before reading entirely
        with requests.get(
            url,
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=False,  # strict: prevent redirect to internal IP
            stream=True,
            verify=True,
        ) as resp:
            # Handle 3xx redirect explicitly if needed, but safe policy flags redirection
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                return None, f"Redirect encountered to '{location}' (redirect following disabled for SSRF safety)", resp.status_code

            content_type = resp.headers.get("Content-Type", "").lower()
            # Accept text or html or general documents
            content_chunks = []
            bytes_received = 0
            for chunk in resp.iter_content(chunk_size=4096):
                bytes_received += len(chunk)
                if bytes_received > MAX_RESPONSE_BYTES:
                    return None, f"Response exceeded maximum allowed size of {MAX_RESPONSE_BYTES} bytes", resp.status_code
                content_chunks.append(chunk)

            raw_bytes = b"".join(content_chunks)
            encoding = resp.encoding or "utf-8"
            html = raw_bytes.decode(encoding, errors="replace")
            return html, "Fetched successfully", resp.status_code

    except requests.exceptions.Timeout:
        return None, f"Connection timed out after {DEFAULT_TIMEOUT}s", None
    except requests.exceptions.SSLError as ssl_err:
        return None, f"TLS/SSL certificate error: {ssl_err}", None
    except requests.exceptions.RequestException as req_err:
        return None, f"Network request error: {req_err}", None
    except Exception as exc:
        return None, f"Fetch error: {exc}", None


def analyze_dom(url: str, html: str | None, base_hostname: str | None = None) -> list[dict[str, Any]]:
    """Inspect DOM / HTML content for phishing indicators.

    Returns:
        List of signal dicts
    """
    signals: list[dict[str, Any]] = []

    parsed_url = urlparse(url)
    page_scheme = (parsed_url.scheme or "").lower()
    page_host = (base_hostname or parsed_url.hostname or "").lower()

    # Transport indicator 1: Page served over insecure HTTP
    if page_scheme == "http":
        signals.append(
            {
                "id": "DOM_INSECURE_TRANSPORT",
                "source": "DOM/Transport",
                "name": "Unencrypted HTTP Transport",
                "description": "Page is served over plain HTTP without TLS/SSL encryption.",
                "points": 18,
            }
        )

    if not html:
        return signals

    soup = BeautifulSoup(html, "html.parser")

    # Find forms and password fields
    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
    hidden_inputs = soup.find_all("input", attrs={"type": re.compile(r"^hidden$", re.I)})
    iframes = soup.find_all("iframe")

    # Transport indicator 2: Password field on insecure HTTP page
    if password_inputs and page_scheme == "http":
        signals.append(
            {
                "id": "DOM_PASSWORD_OVER_HTTP",
                "source": "DOM/Transport",
                "name": "Credential Input on Insecure HTTP Page",
                "description": "Found password input field on a page served without TLS encryption, exposing credentials to interception.",
                "points": 35,
            }
        )

    # Indicator: Form action mismatches
    # A form that submits to an external domain or insecure endpoint
    external_form_targets = []
    insecure_form_actions = []

    for form in forms:
        action = form.get("action", "").strip()
        if not action or action.startswith("#") or action.startswith("javascript:"):
            # Empty or script action might also be suspicious in login forms
            if form.find("input", attrs={"type": re.compile(r"^password$", re.I)}):
                signals.append(
                    {
                        "id": "DOM_FORM_SUSPICIOUS_ACTION",
                        "source": "DOM",
                        "name": "Password Form with Empty/Script Action",
                        "description": "Login form action attribute is missing or points to a JavaScript handler rather than a verified endpoint.",
                        "points": 15,
                    }
                )
            continue

        resolved_action = urljoin(url, action)
        parsed_action = urlparse(resolved_action)
        action_host = (parsed_action.hostname or "").lower()
        action_scheme = (parsed_action.scheme or "").lower()

        if action_scheme == "http" and page_scheme == "https":
            insecure_form_actions.append(resolved_action)

        if action_host and page_host:
            # Check domain mismatch (compare root domains or hosts)
            if action_host != page_host and not action_host.endswith("." + page_host) and not page_host.endswith("." + action_host):
                external_form_targets.append(action_host)

    if external_form_targets:
        targets_str = ", ".join(list(dict.fromkeys(external_form_targets)))
        signals.append(
            {
                "id": "DOM_FORM_ACTION_MISMATCH",
                "source": "DOM",
                "name": "Form Action Domain Mismatch",
                "description": f"Form submits credentials or form data to external domain(s): {targets_str}.",
                "points": 30,
            }
        )

    if insecure_form_actions:
        signals.append(
            {
                "id": "DOM_FORM_ACTION_INSECURE_HTTP",
                "source": "DOM",
                "name": "Form Submits to Plain HTTP",
                "description": "Form submits sensitive payload to an unencrypted HTTP endpoint.",
                "points": 25,
            }
        )

    # Indicator: Elevated hidden input count (> 3)
    if len(hidden_inputs) > 3:
        signals.append(
            {
                "id": "DOM_EXCESSIVE_HIDDEN_INPUTS",
                "source": "DOM",
                "name": "Excessive Hidden Input Fields",
                "description": f"Page contains {len(hidden_inputs)} hidden input fields, typical of phishing credential harvest kits.",
                "points": 14,
            }
        )

    # Indicator: Suspect Iframe embed
    if len(iframes) >= 1:
        # Check if iframes have external sources or full page dimensions
        suspicious_iframes = 0
        for iframe in iframes:
            src = iframe.get("src", "").strip()
            if src.startswith("http://") or src.startswith("https://"):
                iframe_host = (urlparse(src).hostname or "").lower()
                if iframe_host and iframe_host != page_host:
                    suspicious_iframes += 1
        if suspicious_iframes > 0:
            signals.append(
                {
                    "id": "DOM_EXTERNAL_IFRAME",
                    "source": "DOM",
                    "name": "External Iframe Embed",
                    "description": f"Detected {suspicious_iframes} external iframe(s), commonly used in credential phishing overlays.",
                    "points": 15,
                }
            )

    return signals
