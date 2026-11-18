"""
Sentinel Security - Scan History Engine
Version: 0.6.0

Stores scan records in a local JSON file.
"""

import json
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path

HISTORY_FILE = Path(__file__).resolve().parent.parent / "data" / "scan_history.json"

def save_scan(scan_type, target, status):
    """Save a completed scan to the history file."""

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
                history = []

        except (json.JSONDecodeError, OSError):
            history = []

    history.append(record)

    with HISTORY_FILE.open("w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)

    return record

def get_scan_history():
    """Return previously saved scan records."""

    if not HISTORY_FILE.exists():
        return[]

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            history = json.load(file)

        return history if isinstance(history, list) else []

    except (json.JSONDecodeError, OSError):
            return[]

def clear_scan_history():
    """Delete all saved scan history records."""

    if not HISTORY_FILE.exists():
        return True

    try:
        HISTORY_FILE.unlink()
        return True

    except OSError:
        return False