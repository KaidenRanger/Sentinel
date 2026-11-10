"""
Sentinel Security - Main Application
Version: 0.4.0

This file is the main entry point for Sentinel Security.
It provides a command-line menu for scanning local files
and analyzing suspicious URLs.

Users can perform multiple scans or exit the application.
Future updates will introduce a graphical interface.
"""


from pathlib import Path

from scanner import scan_file
from url_scanner import scan_url


def main():
    """Run the Sentinel Security application."""

    print("================================")
    print("       SENTINEL SECURITY        ")
    print("================================")
    print("File and URL Threat Scanner")
    print("Version: 0.4.0")

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

            scan_url(url)

        elif choice == "3":
            print("\nExiting Sentinel Security. Stay safe!")
            break

        else:
            print("\n[ERROR] Invalid selection.")
            print("Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
