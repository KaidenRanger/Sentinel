"""
Sentinel Security - Main Application
Version: 0.6.0

File scanning, static URL analysis, VirusTotal reputation
lookups, and local scan history.
"""

from pathlib import Path

from core.scanner import scan_file
from core.url_scanner import scan_url
from core.threat_intel import check_url_reputation
from core.scan_history import get_scan_history, save_scan


def record_scan(scan_type, target, status):
    """Save scan results without interrupting the scanner."""
    try:
        save_scan(scan_type, target, status)
        print("[INFO] Scan saved to history.")
    except (OSError, TypeError, ValueError) as error:
        print(f"[WARNING] Could not save history: {error}")


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

            result = scan_url(url, return_details=True)

            if not result:
                continue

            status = result["status"]

            if result["warnings"]:
                status += " | Warnings: " + "; ".join(
                    result["warnings"]
                )

            permission = input(
                "\nCheck this URL with VirusTotal? (y/n): "
            ).strip().lower()

            if permission in ("y", "yes"):
                print("\nContacting VirusTotal...")

                vt_result = check_url_reputation(url)

                if vt_result["status"] == "success":
                    print("\n===== VIRUSTOTAL REPORT =====")
                    print(f"Malicious: {vt_result['malicious']}")
                    print(f"Suspicious: {vt_result['suspicious']}")
                    print(f"Harmless: {vt_result['harmless']}")
                    print(f"Undetected: {vt_result['undetected']}")
                    print("=============================")

                    if vt_result["malicious"] > 0:
                        print("[WARNING] Malicious detections reported.")
                    elif vt_result["suspicious"] > 0:
                        print("[WARNING] Suspicious detections reported.")
                    else:
                        print("No malicious detections in this report.")

                    status += (
                        " | VirusTotal: "
                        f"malicious={vt_result['malicious']}, "
                        f"suspicious={vt_result['suspicious']}, "
                        f"harmless={vt_result['harmless']}, "
                        f"undetected={vt_result['undetected']}"
                    )

                else:
                    print(f"\n[INFO] {vt_result['message']}")
                    status += (
                        f" | VirusTotal lookup: {vt_result['status']}"
                    )

            else:
                print("\nVirusTotal lookup skipped.")

            record_scan("url", url, status)

        elif choice == "3":
            print("\n===== SCAN HISTORY =====")

            try:
                history = get_scan_history()
            except OSError as error:
                print(f"[ERROR] Could not read history: {error}")
                continue

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