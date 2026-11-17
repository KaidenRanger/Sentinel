"""
Sentinel Security - File Scanning Engine
Version: 0.6.0

Calculates SHA-256 file hashes and compares them against
a local JSON database of known threat hashes.

This module performs local file analysis and does not
upload files to external services.
"""

import hashlib
import json
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(65536):
            sha256.update(chunk)

    return sha256.hexdigest()


def check_malware_hash(file_hash):
    """Check a hash against our local threat database."""

    database_path = Path(__file__).resolve().parent.parent / "data" / "hashes.json"

    with open(database_path, "r", encoding="utf-8") as database:
        data = json.load(database)

    malicious_hashes = data["malicious_hashes"]

    return malicious_hashes.get(file_hash.lower())


def scan_file(file_path):
    """Scan a file and return its results."""

    path = Path(file_path)

    if not path.is_file():
        print("Error: File does not exist.")
        return None

    file_hash = calculate_sha256(path)
    threat = check_malware_hash(file_hash)

    print("\n===== SENTINEL FILE SCAN =====")
    print(f"File Name: {path.name}")
    print(f"File Size: {path.stat().st_size} bytes")
    print(f"SHA-256: {file_hash}")
    print("==============================\n")

    if threat:
        status = f"THREAT DETECTED ({threat})"
    else:
        status = "No known threats detected"

    print(f"STATUS: {status}")
    print("==============================\n")

    return {
        "file_name": path.name,
        "file_path": str(path),
        "sha256": file_hash,
        "threat": threat,
        "status": status
    }
