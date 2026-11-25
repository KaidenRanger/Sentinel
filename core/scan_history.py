"""
Sentinel Security - Scan History Engine
Version: 0.6.0

Stores scan records in a local JSON file.
"""

import json
import os
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HISTORY_FILE = Path(__file__).resolve().parent.parent / "data" / "scan_history.json"

def save_scan(scan_type, target, status):
    """Save a completed scan to the history file."""

    if scan_type == "url":
        target = sanitize_url(target)

    record = {
        "timestamp": datetime.now(ZoneInfo("America/New_York")).isoformat(),
        "scan_type": scan_type,
        "target": target,
        "status": status
    }

    history = []

    if HISTORY_FILE.exists():
        try:
            with HISTORY_FILE.open("r", encoding="utf-8") as file:
                history = json.load(file)

            if not isinstance(history, list):
                raise ValueError("Invalid scan history format.")

        except (json.JSONDecodeError, OSError) as error:
            raise ValueError(
                "Existing scan history could not be read. "
                "History has been preserved."
            ) from error

    history.append(record)

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=HISTORY_FILE.parent,
            prefix=".scan_history_",
            suffix=".tmp",
            delete=False
        ) as file:
            temp_path = Path(file.name)
            json.dump(history, file, indent=4)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, HISTORY_FILE)

    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    return record

def get_scan_history():
    """Return previously saved scan records."""

    if not HISTORY_FILE.exists():
        return []

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            history = json.load(file)

        return history if isinstance(history, list) else []

    except (json.JSONDecodeError, OSError):
        return []

def clear_scan_history():
    """Delete all saved scan history records."""

    if not HISTORY_FILE.exists():
        return True

    try:
        HISTORY_FILE.unlink()
        return True

    except OSError:
        return False

def sanitize_url(url):
    """Remove sensitive information from URLs before saving."""

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "[Invalid URL]"

        # Remove embedded usernames and passwords.
        netloc = parsed.netloc.rsplit("@", 1)[-1]

        # Remove query parameters and fragments.
        return urlunsplit((
            parsed.scheme,
            netloc,
            parsed.path,
            "",
            ""
        ))

    except (ValueError, TypeError):
        return "[Invalid URL]"