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
