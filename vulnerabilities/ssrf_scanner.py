from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "SSRF",
    "severity": "High",
    "description": "Detects Server-Side Request Forgery via external/internal requests"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    payloads = [
        "http://example.com",
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254"  # AWS metadata
    ]

    findings = []

    try:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            response = send_request(test_url)

            # 🔥 detection patterns
            if any(x in response.lower() for x in [
                "example domain",
                "localhost",
                "meta-data",
                "root:x"
            ]):
                findings.append(payload)

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": f"Possible SSRF detected using: {', '.join(findings)}",
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "No SSRF behavior detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }