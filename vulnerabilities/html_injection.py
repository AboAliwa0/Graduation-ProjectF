from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "HTML Injection",
    "severity": "Medium",
    "description": "Detects reflected HTML injection vulnerabilities"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    payloads = [
        "<h1>TEST123</h1>",
        "<b>INJECT</b>"
    ]

    findings = []

    try:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            response = send_request(test_url)

            if payload.lower() in response.lower():
                findings.append(payload)

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": f"Reflected HTML detected with payloads: {', '.join(findings)}",
                "severity": "Medium"
            }

        return {
            "vulnerable": False,
            "result": "No HTML injection detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }