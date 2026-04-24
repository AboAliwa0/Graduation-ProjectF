import time
from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "SQL Injection",
    "severity": "High",
    "description": "Detects SQL injection vulnerabilities using multiple techniques"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    findings = []

    try:
        # -----------------------
        # 🔹 Boolean-based
        # -----------------------
        payload_true = "' OR '1'='1"
        payload_false = "' OR '1'='2"

        res_true = send_request(f"{url}?{param}={payload_true}")
        res_false = send_request(f"{url}?{param}={payload_false}")

        if res_true != res_false:
            findings.append("Boolean-based SQL Injection detected")

        # -----------------------
        # 🔹 Error-based
        # -----------------------
        error_payload = "'"
        res_error = send_request(f"{url}?{param}={error_payload}")

        errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "warning",
            "pdo",
            "odbc"
        ]

        if any(e in res_error.lower() for e in errors):
            findings.append("Error-based SQL Injection detected")

        # -----------------------
        # 🔹 Time-based
        # -----------------------
        start = time.time()
        send_request(f"{url}?{param}=' OR SLEEP(3)--")
        delay = time.time() - start

        if delay > 2.5:
            findings.append("Time-based SQL Injection detected")

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": " | ".join(findings),
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "No SQL Injection detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }