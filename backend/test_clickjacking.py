from backend.plugins.clickjacking import ClickjackingScanner

scanner = ClickjackingScanner()

result = scanner.execute(
    "https://0a9d00c80313e6fe81ab39f5003f00bb.web-security-academy.net/"
)

print("=" * 60)
print(type(result))
print("=" * 60)

print("Title:", result.title)
print("Vulnerable:", result.vulnerable)
print("Severity:", result.severity)
print("Confidence:", result.confidence)
print("Description:", result.description)
print("Recommendation:", result.recommendation)
print("Execution Time:", result.execution_time)
print("Evidence:", result.evidence)