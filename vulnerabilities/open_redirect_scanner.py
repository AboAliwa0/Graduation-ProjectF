import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Open Redirect",
    "severity": "High",
    "description": "Detects open redirect vulnerabilities via common parameters"
}

inputs = []  # 👈 no user input needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    session = requests.Session()

    redirect_params = [
        "next", "url", "target", "redirect", "redir", "return", "continue",
        "dest", "destination", "path", "uri", "view", "checkout", "return_to"
    ]

    malicious_url = "http://evil.com/redirect_test"
    findings = []

    try:
        for param in redirect_params:
            test_url = f"{url}?{param}={malicious_url}"

            try:
                r = session.get(test_url, allow_redirects=True, timeout=10)

                # 🔥 check final redirect
                if r.url.startswith(malicious_url):
                    findings.append(f"Vulnerable via parameter '{param}'")
                    break

            except:
                continue

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": " | ".join(findings),
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "No open redirect detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }