"""
Sentinel Security - Main Application
Version: 0.3.2

This file serves as the main entry point for Sentinel Security.
It allows users to enter file paths for security scanning.

If a file cannot be found, the user can retry or exit.
After a successful scan, the user can choose to scan
another file or close the application.
"""

from pathlib import Path
from scanner import scan_file


def main():
    """Run the Sentinel Security application."""

    print("================================")
    print("       SENTINEL SECURITY        ")
    print("================================")
    print("File and URL Threat Scanner")
    print("Version: 0.3.2")

    while True:
        file_path = input(
            "\nEnter a file path to scan (or 'exit' to quit): "
        ).strip().strip('"')

        # Allow the user to exit Sentinel
        if file_path.lower() in ("exit", "quit", "q"):
            print("\nExiting Sentinel Security. Stay safe!")
            break

        # Check whether the file exists
        if not Path(file_path).is_file():
            print("\n[ERROR] File not found.")
            print("Please check the path and try again.")
            continue

        # Scan the file
        scan_file(file_path)

        # Ask whether the user wants to scan another file
        choice = input(
            "\nWould you like to scan another file? (y/n): "
        ).strip().lower()

        if choice not in ("y", "yes"):
            print("\nExiting Sentinel Security. Goodbye!")
            break


if __name__ == "__main__":
    main()