"""Module A: Lexical URL Analysis.

Analyzes raw and parsed URL features:
- Excessive URL length (>75 chars)
- IP address used as hostname (IPv4 / IPv6)
- Presence of '@' symbol (userinfo confusion / credentials spoofing)
- Excessive subdomain depth (>3 levels)
- Excessive special characters / suspicious punctuation in host or path
- Brand keyword spoofing / target brand keywords present in subdomain or path
- Suspicious top-level domain (TLD) or hyphen abuse
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

# Popular target brands frequently impersonated in phishing attacks
TARGET_BRANDS: tuple[str, ...] = (
    "paypal",
    "apple",
    "google",
    "microsoft",
    "netflix",
    "amazon",
    "facebook",
    "instagram",
    "wellsfargo",
    "chase",
    "bankofamerica",
    "citibank",
    "dropbox",
    "adobe",
    "linkedin",
    "twitter",
    "coinbase",
    "binance",
    "metamask",
    "outlook",
    "office365",
    "yahoo",
    "steam",
    "ebay",
    "walmart",
)

# Common suspicious top-level domains frequently abused for low-cost phishing
SUSPICIOUS_TLDS: tuple[str, ...] = (
    "top",
    "xyz",
    "club",
    "work",
    "click",
    "fit",
    "rest",
    "gq",
    "ml",
    "cf",
    "tk",
    "ga",
    "buzz",
    "surf",
    "icu",
    "cam",
)


def is_ip_address(host: str) -> bool:
    """Check if the host string represents an IPv4 or IPv6 address."""
    # Strip brackets if IPv6 host like [2001:db8::1]
    cleaned = host.strip("[]")
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def analyze_lexical(raw_url: str) -> dict[str, Any]:
    """Inspect lexical characteristics of the provided URL and return signals.

    Returns:
        dict containing:
            - normalized_url: sanitized/normalized URL
            - parsed: component breakdown (scheme, netloc, path, etc.)
            - signals: list of triggered signal dicts:
                - id: unique identifier
                - source: 'URL'
                - name: short title
                - description: detailed rationale
                - points: positive integer weight
    """
    signals: list[dict[str, Any]] = []

    # Clean leading/trailing whitespaces
    url = raw_url.strip()
    if not url:
        return {
            "normalized_url": "",
            "parsed": {},
            "signals": [
                {
                    "id": "LEX_EMPTY_URL",
                    "source": "URL",
                    "name": "Empty URL Input",
                    "description": "No valid URL was provided for analysis.",
                    "points": 30,
                }
            ],
        }

    # If scheme missing, default to http:// for parsing purposes
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        working_url = "http://" + url
    else:
        working_url = url

    try:
        parsed = urlparse(working_url)
    except Exception as exc:
        return {
            "normalized_url": url,
            "parsed": {},
            "signals": [
                {
                    "id": "LEX_INVALID_FORMAT",
                    "source": "URL",
                    "name": "Malformed URL Syntax",
                    "description": f"URL parsing failed: {exc}",
                    "points": 40,
                }
            ],
        }

    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # 1. URL Length check (> 75 chars)
    # Phishers often use very long URLs to hide malicious domain or encode tokens
    if len(url) > 75:
        signals.append(
            {
                "id": "LEX_LONG_URL",
                "source": "URL",
                "name": "Excessive URL Length",
                "description": f"URL length is {len(url)} characters (> 75 limit).",
                "points": 15,
            }
        )

    # 2. IP address as host
    if is_ip_address(hostname):
        signals.append(
            {
                "id": "LEX_IP_HOST",
                "source": "URL",
                "name": "IP Address as Hostname",
                "description": f"Host '{hostname}' is a raw IP address rather than a registered domain name.",
                "points": 30,
            }
        )

    # 3. '@' symbol in URL
    # Can be used to disguise destinations before username auth delimiter
    if "@" in url:
        signals.append(
            {
                "id": "LEX_AT_SYMBOL",
                "source": "URL",
                "name": "URL Contains '@' Symbol",
                "description": "The '@' character can trick users and browsers by passing user credentials prior to destination host.",
                "points": 25,
            }
        )

    # 4. Subdomain depth (> 3 levels)
    # e.g., login.security.update.example.com has subdomains ['login', 'security', 'update']
    # If host is an IP, subdomain split doesn't apply
    if hostname and not is_ip_address(hostname):
        parts = hostname.split(".")
        # Typically last 1-2 parts are domain + TLD (e.g. example.com or example.co.uk)
        # Depth > 3 means 4 or more labels (e.g. a.b.c.example.com has 5 parts, depth 4)
        # Depth = total parts - 1
        subdomain_parts = parts[:-2] if len(parts) >= 2 else []
        if len(subdomain_parts) > 3 or len(parts) > 4:
            signals.append(
                {
                    "id": "LEX_DEEP_SUBDOMAINS",
                    "source": "URL",
                    "name": "Excessive Subdomain Depth",
                    "description": f"Hostname '{hostname}' has {len(parts)} label components (subdomain depth > 3).",
                    "points": 18,
                }
            )

    # 5. Special characters and hyphen abuse in hostname/path
    # Phishing domains frequently use multiple hyphens or abnormal characters
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        signals.append(
            {
                "id": "LEX_MULTIPLE_HYPHENS",
                "source": "URL",
                "name": "Multiple Hyphens in Domain",
                "description": f"Hostname contains {hyphen_count} hyphens, a common pattern in typosquatting and impersonation.",
                "points": 12,
            }
        )

    # Suspicious special characters in netloc or path (like %20, double slashes, semicolons)
    special_chars = re.findall(r"[\%~\|\<\>\^\`\{\}]", url)
    if len(special_chars) >= 3:
        signals.append(
            {
                "id": "LEX_SUSPICIOUS_CHARS",
                "source": "URL",
                "name": "Abnormal Special Character Density",
                "description": f"URL contains multiple encoded or abnormal characters ({len(special_chars)} instances).",
                "points": 10,
            }
        )

    # Double slashes after the scheme path (e.g., http://example.com//redirect)
    if "//" in (parsed.path + ("?" + query if query else "")):
        signals.append(
            {
                "id": "LEX_DOUBLE_SLASH_PATH",
                "source": "URL",
                "name": "Consecutive Slashes in Path",
                "description": "Path contains consecutive slashes ('//') frequently used for open-redirect evasion.",
                "points": 12,
            }
        )

    # 6. Brand keyword spoofing
    # Check if a known brand keyword appears in subdomains or path, especially if the root domain is NOT that brand
    matched_brands: list[str] = []
    # Identify the base domain roughly (e.g. brand.com)
    for brand in TARGET_BRANDS:
        # Check if brand appears in hostname or path
        in_host = brand in hostname
        in_path = brand in path.lower() or (query and brand in query.lower())
        if in_host or in_path:
            # Check if domain IS legit brand domain (e.g. hostname is exactly brand.com or paypal.com)
            is_legit_domain = hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")
            if not is_legit_domain:
                matched_brands.append(brand)

    if matched_brands:
        unique_brands = list(dict.fromkeys(matched_brands))
        signals.append(
            {
                "id": "LEX_BRAND_SPOOFING",
                "source": "URL",
                "name": "Target Brand Keyword Spoofing",
                "description": f"Detected high-value brand keyword(s) {unique_brands} embedded in an unofficial domain or URL path.",
                "points": 25,
            }
        )

    # 7. Suspicious TLD check
    if "." in hostname and not is_ip_address(hostname):
        tld = hostname.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            signals.append(
                {
                    "id": "LEX_SUSPICIOUS_TLD",
                    "source": "URL",
                    "name": "High-Risk Top-Level Domain",
                    "description": f"The domain uses '.{tld}', a TLD frequently associated with spam and phishing campaigns.",
                    "points": 15,
                }
            )

    return {
        "normalized_url": working_url,
        "raw_url": raw_url,
        "parsed": {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "hostname": hostname,
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
        },
        "signals": signals,
    }
