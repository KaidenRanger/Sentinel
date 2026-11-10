import hashlib
import json
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(65536):  # Read the file in 64KB chunks
            sha256.update(chunk)

    return sha256.hexdigest()


def check_malware_hash(file_hash):
    """Check a hash against our local threat database."""

    database_path = Path(__file__).resolve().parent / "hashes.json"

    with open(database_path, "r", encoding="utf-8") as database:
        data = json.load(database)

    malicious_hashes = data["malicious_hashes"]

    return malicious_hashes.get(file_hash.lower())


def scan_file(file_path):
    """Scan a file and check for known threats."""

    path = Path(file_path)

    if not path.is_file():
        print("Error: File does not exist.")
        return

    file_hash = calculate_sha256(path)
    threat = check_malware_hash(file_hash)

    print("\n===== SENTINEL FILE SCAN =====")
    print(f"File Name: {path.name}")
    print(f"File Size: {path.stat().st_size} bytes")
    print(f"SHA-256: {file_hash}")
    print("==============================\n")


    if threat:
            print(f"STATUS: THREAT DETECTED ({threat})")
    else:
            print("STATUS: No known threats detected")

    print("==============================\n")


"""
Sentinel Security - File Scanning Engine
Version: 0.3.1

This module handles Sentinel's file analysis functionality.
It calculates SHA-256 hashes, collects basic file information,
and compares file hashes against a local threat database.

Files matching known threat signatures are flagged for review.
A file without a matching hash is not necessarily safe.

Future updates will include advanced malware detection,
file signature analysis, and threat intelligence integration.
"""