import requests
from bs4 import BeautifulSoup

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "CSRF",
    "severity": "Medium",
    "description": "Checks for missing CSRF protection in forms"
}

inputs = []  # 👈 no user input needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    try:
        res = requests.get(url, timeout=10)
        html = res.text.lower()

        # 🔹 check headers
        csrf_headers = [
            "x-csrf-token",
            "csrf-token",
            "xsrf-token"
        ]

        for header in res.headers:
            if header.lower() in csrf_headers:
                return {
                    "vulnerable": False,
                    "result": "CSRF protection header detected",
                    "severity": "Low"
                }

        # 🔹 check forms
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return {
                "vulnerable": False,
                "result": "No forms detected",
                "severity": "Low"
            }

        for form in forms:
            inputs = form.find_all("input")

            for inp in inputs:
                name = inp.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    return {
                        "vulnerable": False,
                        "result": "CSRF token found in form",
                        "severity": "Low"
                    }

        # 🔥 no protection found
        return {
            "vulnerable": True,
            "result": "No CSRF protection detected in forms",
            "severity": "Medium"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }