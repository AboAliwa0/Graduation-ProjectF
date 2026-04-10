from datetime import datetime

def get_severity(result):
    if "[+]" in result:
        return "HIGH"
    elif "[!]" in result:
        return "MEDIUM"
    elif "[*]" in result:
        return "LOW"
    else:
        return "INFO"


def generate_report(results, target):
    now = datetime.now()
    date_time = now.strftime("%Y-%m-%d %H:%M:%S")

    with open("report.txt", "w") as file:
        file.write("=== Vulnerability Scan Report ===\n\n")
        file.write(f"Target: {target}\n")
        file.write(f"Date & Time: {date_time}\n\n")

        file.write("Results:\n")
        file.write("-" * 40 + "\n")

        for result in results:
            severity = get_severity(result)
            file.write(f"{result}  --> Severity: {severity}\n")

    print("[+] Report saved as report.txt")