
"""
Sentinel Security - Main Application
Version: 0.6.0

Command-line cybersecurity tool for file hash scanning,
static URL analysis, optional VirusTotal reputation lookups,
and local scan history.
"""

from pathlib import Path

from scanner import scan_file
from url_scanner import scan_url
from threat_intel import check_url_reputation
from scan_history import get_scan_history, save_scan


def record_scan(scan_type, target, status):
    """Save a scan without interrupting the scanner on write errors."""
    try:
        save_scan(scan_type, target, status)
        print("[INFO] Scan saved to history.")
    except (OSError, TypeError, ValueError) as error:
        print(f"[WARNING] Could not save scan history: {error}")


def main():
    """Run the Sentinel Security application."""

    print("================================")
    print("       SENTINEL SECURITY        ")
    print("================================")
    print("File and URL Threat Scanner")
    print("Version: 0.6.0")

    while True:
        print("\n===== MAIN MENU =====")
        print("1. Scan a File")
        print("2. Scan a URL")
        print("3. View Scan History")
        print("4. Exit Sentinel")

        choice = input("\nSelect an option (1-4): ").strip()

        if choice == "1":
            file_path = input(
                "\nEnter file path (or 'back' to return): "
            ).strip().strip('"')

            if file_path.lower() == "back":
                continue

            if not Path(file_path).is_file():
                print("\n[ERROR] File not found.")
                print("Please try again.")
                continue

            try:
                result = scan_file(file_path)

                if result is not None:
                    record_scan(
                        "file",
                        result["file_path"],
                        result["status"]
                    )

            except (OSError, ValueError, KeyError) as error:
                print(f"\n[ERROR] File scan failed: {error}")

        elif choice == "2":
            url = input(
                "\nEnter URL (or 'back' to return): "
            ).strip()

            if url.lower() == "back":
                continue

            valid_url = scan_url(url)

            if not valid_url:
                continue

            status = "Static URL analysis completed; review console warnings"

            permission = input(
                "\nCheck this URL with VirusTotal? (y/n): "
            ).strip().lower()

            if permission in ("y", "yes"):
                print("\nContacting VirusTotal...")

                result = check_url_reputation(url)

                if result["status"] == "success":
                    print("\n===== VIRUSTOTAL REPORT =====")
                    print(f"Malicious: {result['malicious']}")
                    print(f"Suspicious: {result['suspicious']}")
                    print(f"Harmless: {result['harmless']}")
                    print(f"Undetected: {result['undetected']}")
                    print("=============================")

                    if result["malicious"] > 0:
                        print("[WARNING] Malicious detections reported.")
                    elif result["suspicious"] > 0:
                        print("[WARNING] Suspicious detections reported.")
                    else:
                        print("No malicious detections in this report.")

                    status = (
                        "Static analysis completed; "
                        f"VirusTotal malicious={result['malicious']}, "
                        f"suspicious={result['suspicious']}, "
                        f"harmless={result['harmless']}, "
                        f"undetected={result['undetected']}"
                    )

                else:
                    print(f"\n[INFO] {result['message']}")
                    status = (
                        "Static analysis completed; "
                        f"VirusTotal lookup: {result['status']}"
                    )

            else:
                print("\nVirusTotal lookup skipped.")

            record_scan("url", url, status)

        elif choice == "3":
            print("\n===== SCAN HISTORY =====")

            history = get_scan_history()

            if not history:
                print("No previous scans recorded.")
            else:
                for index, record in enumerate(history, start=1):
                    print(f"\nScan #{index}")
                    print(f"Time: {record['timestamp']}")
                    print(f"Type: {record['scan_type']}")
                    print(f"Target: {record['target']}")
                    print(f"Status: {record['status']}")

            print("========================")

        elif choice == "4":
            print("\nExiting Sentinel Security. Stay safe!")
            break

        else:
            print("\n[ERROR] Invalid selection.")
            print("Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()