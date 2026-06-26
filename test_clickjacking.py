from backend.plugins.clickjacking import ClickjackingScanner

scanner = ClickjackingScanner()

url = "https://0a9d00c80313e6fe81ab39f5003f00bb.web-security-academy.net/"

print("=" * 60)
print("TESTING HTTP CLIENT")
print("=" * 60)

try:
    response = scanner.client.get(url)

    print("STATUS:", response.status_code)
    print("SERVER:", response.headers.get("Server"))
    print("X-Frame-Options:", response.headers.get("X-Frame-Options"))
    print("Content-Security-Policy:", response.headers.get("Content-Security-Policy"))

except Exception as e:
    import traceback
    traceback.print_exc()