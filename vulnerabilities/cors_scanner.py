import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "CORS Misconfiguration",
    "severity": "High",
    "description": "Detects insecure CORS policies allowing unauthorized cross-origin access"
}

inputs = []  # 👈 no user input needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    session = requests.Session()

    findings = []

    test_origins = [
        "http://evil.com",
        "https://evil.com",
        "null"
    ]

    try:
        for origin in test_origins:
            r = session.get(url, headers={"Origin": origin}, timeout=10)

            aca_origin = r.headers.get("Access-Control-Allow-Origin", "")
            aca_creds = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            # 🔥 Case 1: wildcard + credentials
            if aca_origin == "*" and aca_creds == "true":
                findings.append({
                    "issue": "Wildcard (*) with credentials allowed",
                    "severity": "Critical"
                })

            # 🔥 Case 2: reflected origin
            elif aca_origin == origin:
                findings.append({
                    "issue": f"Reflects arbitrary origin ({origin})",
                    "severity": "High"
                })

        # 🔥 Preflight test
        headers = {
            "Origin": "http://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization"
        }

        r2 = session.options(url, headers=headers, timeout=10)

        aca_origin2 = r2.headers.get("Access-Control-Allow-Origin", "")
        aca_creds2 = r2.headers.get("Access-Control-Allow-Credentials", "").lower()

        if aca_origin2 == "http://evil.com" or (aca_origin2 == "*" and aca_creds2 == "true"):
            findings.append({
                "issue": "Preflight (OPTIONS) misconfigured",
                "severity": "High"
            })

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }

    # -----------------------
    # 📊 RESULT
    # -----------------------

    if findings:
        issues = " | ".join([f["issue"] for f in findings])
        max_severity = max(f["severity"] for f in findings)

        return {
            "vulnerable": True,
            "result": issues,
            "severity": max_severity
        }

    return {
        "vulnerable": False,
        "result": "CORS configuration appears secure",
        "severity": "Low"
    }