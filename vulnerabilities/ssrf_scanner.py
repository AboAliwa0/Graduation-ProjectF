from utils import get_session
from report import section, vuln, safe

def check_ssrf_basic(url, param):
    section("SSRF")

    session = get_session()

    payloads = [
        "http://example.com",
        "http://127.0.0.1"
    ]

    detected = False

    for p in payloads:
        try:
            full = f"{url}?{param}={p}"
            r = session.get(full)

            print(f"Testing: {p} -> {r.status_code}")

            if "example" in r.text.lower():
                detected = True

        except:
            pass

    if detected:
        vuln("Possible SSRF behavior", "MEDIUM")
    else:
        safe("No SSRF detected")