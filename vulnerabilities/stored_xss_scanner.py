import requests
from bs4 import BeautifulSoup

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Stored XSS",
    "severity": "Critical",
    "description": "Detects stored XSS by injecting payloads and checking persistence"
}

inputs = ["submit_path", "param_name"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, submit_path=None, param_name=None):
    if not submit_path or not param_name:
        return {
            "vulnerable": False,
            "result": "submit_path and param_name required",
            "severity": "Low"
        }

    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'\"><script>alert(1)</script>"
    ]

    session = requests.Session()
    submit_url = url.rstrip("/") + "/" + submit_path.lstrip("/")

    try:
        for payload in payloads:

            # 🔹 Step 1: submit payload
            data = {param_name: payload}
            session.post(submit_url, data=data, timeout=10)

            # 🔹 Step 2: fetch page
            res = session.get(url, timeout=10)
            html = res.text.lower()

            # 🔹 Step 3: check persistence
            if payload.lower() in html:
                return {
                    "vulnerable": True,
                    "result": f"Stored XSS detected using payload: {payload}",
                    "severity": "Critical"
                }

        return {
            "vulnerable": False,
            "result": "No stored XSS detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }