from scanner import scan_file
def main():
    print("================================")
    print("       SENTINEL SECURITY        ")
    print("================================")
    print("File and URL Threat Scanner")
    print("0.2.0")
    print("Status: Ready")

    file_path = input("\nEnter a file path to scan: ")

    scan_file(file_path.strip().strip('"'))

if __name__ == "__main__":
    main()


"""
Sentinel Security - Main Application
Version: 0.3.1

This file serves as the main entry point for Sentinel Security.
It initializes the application and allows users to select files
for security scanning. It connects the user interface with the
file scanning engine to display analysis results.

Future updates will introduce URL scanning and a graphical
user interface (GUI).
"""