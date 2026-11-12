"""
Sentinel Security - Main Application
Version: 0.5.0

Command-line cybersecurity tool for file hash scanning,
static URL analysis, and optional VirusTotal reputation lookups.

Provides an interactive menu and requests user permission
before contacting VirusTotal.
"""


from pathlib import Path

from scanner import scan_file
from url_scanner import scan_url
from threat_intel import check_url_reputation


def main():
    """Run the Sentinel Security application."""

    print("================================")
    print("       SENTINEL SECURITY        ")
    print("================================")
    print("File and URL Threat Scanner")
    print("Version: 0.5.0")

    while True:
        print("\n===== MAIN MENU =====")
        print("1. Scan a File")
        print("2. Scan a URL")
        print("3. Exit Sentinel")

        choice = input("\nSelect an option (1-3): ").strip()

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
                scan_file(file_path)
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

            # Ask permission before contacting VirusTotal
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

                else:
                    print(f"\n[INFO] {result['message']}")

            else:
                print("\nVirusTotal lookup skipped.")


        elif choice == "3":
            print("\nExiting Sentinel Security. Stay safe!")
            break

        else:
            print("\n[ERROR] Invalid selection.")
            print("Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
