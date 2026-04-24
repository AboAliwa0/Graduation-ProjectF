import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Information Disclosure",
    "severity": "Medium",
    "description": "Detects sensitive information leakage in headers or response body"
}

inputs = []  # 👈 no user input needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    try:
        res = requests.get(url, timeout=10)
        body = res.text.lower()

        findings = []

        # 🔹 Check headers
        server = res.headers.get("Server", "")
        powered = res.headers.get("X-Powered-By", "")

        if server:
            findings.append(f"Server header exposed: {server}")

        if powered:
            findings.append(f"X-Powered-By exposed: {powered}")

        # 🔹 Check body leaks
        keywords = [
            "error",
            "exception",
            "stack trace",
            "apache",
            "nginx",
            "sql syntax"
        ]

        for k in keywords:
            if k in body:
                findings.append(f"Keyword found: {k}")
                break

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": " | ".join(findings),
                "severity": "Medium"
            }

        return {
            "vulnerable": False,
            "result": "No information disclosure detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }