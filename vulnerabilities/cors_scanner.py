from utils import get_session, rate_sleep
from report import section, vuln, safe, log


def check_cors(url):
    section("CORS Misconfiguration")
    session    = get_session()
    vulnerable = False

    origins = [
        "http://evil.com",
        "https://evil.com",
        "null",
    ]

    for origin in origins:
        try:
            rate_sleep()
            r = session.get(url, headers={"Origin": origin}, timeout=10)

            aca_origin = r.headers.get("Access-Control-Allow-Origin", "")
            aca_creds  = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            log(f"[*] Origin: {origin:25} -> ACA-Origin: {aca_origin}")

            if aca_origin == "*" and aca_creds == "true":
                vuln(
                    "CORS allows credentials with wildcard (*)",
                    "CRITICAL",
                    verify_cmd=f'curl -H "Origin: {origin}" -I {url}'
                )
                vulnerable = True

            elif aca_origin == origin:
                vuln(
                    f"CORS reflects arbitrary origin ({origin})",
                    "HIGH",
                    verify_cmd=f'curl -H "Origin: {origin}" -I {url}'
                )
                vulnerable = True

        except Exception as e:
            log(f"[-] Error testing origin '{origin}': {e}")

    # Preflight OPTIONS test
    try:
        rate_sleep()
        preflight_headers = {
            "Origin":                         "http://evil.com",
            "Access-Control-Request-Method":  "POST",
            "Access-Control-Request-Headers": "Authorization",
        }
        r2          = session.options(url, headers=preflight_headers, timeout=10)
        aca_origin2 = r2.headers.get("Access-Control-Allow-Origin", "")
        aca_creds2  = r2.headers.get("Access-Control-Allow-Credentials", "").lower()

        log(f"[*] Preflight OPTIONS -> ACA-Origin: {aca_origin2}")

        if aca_origin2 == "http://evil.com" or (aca_origin2 == "*" and aca_creds2 == "true"):
            vuln(
                "CORS Preflight (OPTIONS) is misconfigured",
                "HIGH",
                verify_cmd=f'curl -X OPTIONS -H "Origin: http://evil.com" -I {url}'
            )
            vulnerable = True

    except Exception as e:
        log(f"[-] Preflight test error: {e}")

    if not vulnerable:
        safe("CORS configuration appears secure")
