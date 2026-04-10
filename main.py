from vulnerabilities import path_traversal, file_upload, blind_xss
from report import generate_report

def main():
    target = input("Enter target URL: ")

    scanners = [
        path_traversal,
        file_upload,
        blind_xss
    ]

    results = []

    print("\n=== Scan Started ===\n")

    for scanner in scanners:
        try:
            result = scanner.scan(target)
        except Exception as e:
            result = f"[!] Error in {scanner.__name__}: {str(e)}"

        print(result)
        results.append(result)

    print("\n=== Scan Finished ===\n")

    # حفظ التقرير
    generate_report(results, target)


if __name__ == "__main__":
    main()