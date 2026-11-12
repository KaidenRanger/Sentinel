"""
Sentinel Security - Threat Intelligence Engine
Version: 0.5.0

Integrates with the VirusTotal API v3 to retrieve existing
URL reputation reports.

Requires the VT_API_KEY environment variable.

Only retrieves existing reports. Does not submit URLs for
new scans or connect directly to the target website.

External lookups require user permission in main.py.
"""

import base64
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

def check_url_reputation(url):
    """Retrieve an existing VirusTotal URL report."""

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured."
        }
    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = (
        f"https://www.virustotal.com/api/v3/urls/{url_id}"
    )

    request = Request(
        endpoint,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    )

    try:
        with urlopen(request, timeout=10) as response:
            data = json.load(response)

            stats = data["data"]["attributes"][
                "last_analysis_stats"
            ]
            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

    except HTTPError as error:
        message = {
            401: "Invalid or unauthorized API key.",
            403: "Access denied by VirusTotal.",
            404: "No existing report found for this URL.",
            429: "VirusTotal API rate limit reached."
        }

        return {
            "status": "error",
            "message": message.get(
                error.code,
                f"VirusTotal returned HTTP {error.code}."
            )
        }

    except (URLError, TimeoutError):
        return {
            "status": "error",
            "message": "Network error or request timed out."
        }

    except (ValueError, KeyError, TypeError):
        return {
            "status": "error",
            "message": "Unexpected VirusTotal response."
        }