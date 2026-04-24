import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Clickjacking",
    "severity": "Medium",
    "description": "Checks if site can be embedded in iframe (missing X-Frame-Options or CSP)"
}

inputs = []  # 👈 no extra inputs needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    try:
        r = requests.get(url, timeout=10)

        x_frame = r.headers.get("X-Frame-Options", "").lower()
        csp = r.headers.get("Content-Security-Policy", "").lower()

        # -----------------------
        # 📊 ANALYSIS
        # -----------------------

        if not x_frame and "frame-ancestors" not in csp:
            return {
                "vulnerable": True,
                "result": "Missing X-Frame-Options and CSP frame-ancestors",
                "severity": "High"
            }

        elif "allow-from" in x_frame:
            return {
                "vulnerable": True,
                "result": f"X-Frame-Options allows embedding from specific origin",
                "severity": "Medium"
            }

        else:
            return {
                "vulnerable": False,
                "result": "Clickjacking protection detected (X-Frame-Options or CSP)",
                "severity": "Low"
            }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }