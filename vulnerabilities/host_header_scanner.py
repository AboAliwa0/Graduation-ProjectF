import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Host Header Injection",
    "severity": "High",
    "description": "Detects host header injection and poisoning vulnerabilities"
}

inputs = []  # 👈 no user input needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    session = requests.Session()
    evil_host = "evil.com"

    test_headers = [
        {"Host": evil_host},
        {"X-Forwarded-Host": evil_host},
        {"X-Host": evil_host},
        {"X-Forwarded-Server": evil_host},
        {"Forwarded": f"for=127.0.0.1;host={evil_host}"},
    ]

    findings = []

    try:
        # 🔹 baseline
        normal = session.get(url, timeout=10)
        base_len = len(normal.text)

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Baseline request failed: {str(e)}",
            "severity": "Low"
        }

    for headers in test_headers:
        header_name = list(headers.keys())[0]

        try:
            r = session.get(url, headers=headers, timeout=10)
            response = r.text
            current_len = len(response)

            # 🔥 reflection
            if evil_host in response:
                findings.append({
                    "issue": f"Reflected Host Header via {header_name}",
                    "severity": "High"
                })
                continue

            # 🔥 poisoning
            poisoned = [
                f"href=\"http://{evil_host}",
                f"href='http://{evil_host}",
                f"action=\"http://{evil_host}",
                f"url=http://{evil_host}",
            ]

            if any(p in response for p in poisoned):
                findings.append({
                    "issue": f"Poisoned response via {header_name}",
                    "severity": "High"
                })
                continue

            # 🔥 response diff
            if abs(current_len - base_len) > 50:
                findings.append({
                    "issue": f"Response changed via {header_name}",
                    "severity": "Medium"
                })

        except:
            continue

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
        "result": "No Host Header issues detected",
        "severity": "Low"
    }