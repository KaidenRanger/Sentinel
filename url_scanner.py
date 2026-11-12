"""
Sentinel Security - URL Scanning Engine
Version: 0.5.0

Performs static URL analysis to identify suspicious
characteristics associated with phishing and malicious links.

Checks URL structure, HTTPS usage, IP-based hostnames,
user information, URL length, and Punycode domains.

The scanner does not visit websites or download content.
Results are heuristic indicators, not safety guarantees.
"""

import ipaddress
import re
from urllib.parse import urlsplit


def scan_url(url):
    """Analyze a URL for basic security risk indicators."""

    url = url.strip()

    print("\n===== SENTINEL URL SCAN ====")
    print(f"URL: {url}")

    # Parse the URL without opening the website
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        print("STATUS: Invalid URL.")
        return False

    # Require an HTTP(S) URL with a valid hostname
    if parsed.scheme.lower() not in ("http", "https"):
        print("STATUS: Invalid or unsupported URL scheme")
        return False

    if not hostname or any(c.isspace() for c in url):
        print("STATUS: Invalid URL")
        return False

    if not (1 <= len(hostname) <= 253):
        print("STATUS: Invalid hostname (length out of range)")
        return False

    # Check that the hostname can be represented in DNS
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        print("STATUS: Invalid hostname (IDNA encoding failed)")
        return False

    labels = ascii_hostname.rstrip(".").split(".")

    # Reject invalid characters in DNS hostname labels
    if any(
        not re.fullmatch(r"[A-Za-z0-9-]+", label)
        for label in labels
    ):
        print("STATUS: Invalid hostname characters")
        return False

    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        print("STATUS: Invalid hostname (DNS formatting failed)")
        return False

    warnings = []

    # Check for an unencrypted HTTP connection
    if parsed.scheme.lower() == "http":
        warnings.append(
            "URL does not use HTTPS (unencrypted connection)"
        )

    # Check whether the hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        warnings.append(
            "URL uses an IP address instead of a domain name"
        )
    except ValueError:
        pass

    # Check for user information in the URL
    if "@" in parsed.netloc:
        warnings.append(
            "URL contains user information (potential phishing)"
        )

    # Check for unusually long URLs
    if len(url) > 200:
        warnings.append(
            "URL is unusually long (potential phishing)"
        )

    # Check for encoded internationalized domain names
    if "xn--" in ascii_hostname:
        warnings.append(
            "URL contains a Punycode domain label"
        )

    print(f"Hostname: {hostname}")
    print(f"Scheme: {parsed.scheme.upper()}")

    if port is not None:
        print(f"Port: {port}")

    if warnings:
        print("\nSTATUS: REVIEW RECOMMENDED")
        for warning in warnings:
            print(f"[WARNING] {warning}")
    else:
        print("\nSTATUS: No suspicious URL indicators detected")

    print("============================\n")

    return True
