from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "SSRF",
    "severity": "High",
    "description": "Detects SSRF via internal resource access"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    payload = "http://127.0.0.1"

    try:
        test_url = f"{url}?{param}={payload}"
        response = send_request(test_url)

        if any(x in response.lower() for x in ["127.0.0.1", "localhost"]):
            return {
                "vulnerable": True,
                "result": "Internal resource access detected (127.0.0.1)",
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "No SSRF detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }