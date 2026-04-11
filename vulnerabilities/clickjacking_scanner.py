from utils import get_session, rate_sleep
from report import section, vuln, safe, log

def check_clickjacking(url):
    section("Clickjacking")
    session = get_session()
    vulnerable = False

    try:
        rate_sleep()
        r = session.get(url, timeout=10)

        x_frame_options = r.headers.get("X-Frame-Options", "").lower()
        content_security_policy = r.headers.get("Content-Security-Policy", "").lower()

        log(f"[*] URL: {url}")
        log(f"[*] X-Frame-Options: {x_frame_options if x_frame_options else 'Not Set'}")
        log(f"[*] Content-Security-Policy: {content_security_policy if content_security_policy else 'Not Set'}")

        if not x_frame_options and "frame-ancestors" not in content_security_policy:
            vuln(
                "Clickjacking vulnerability detected (Missing X-Frame-Options and frame-ancestors in CSP)",
                "HIGH",
                verify_cmd=f'Check manually by embedding {url} in an iframe.'
            )
            vulnerable = True
        elif "allow-from" in x_frame_options:
            vuln(
                f"Clickjacking vulnerability detected (X-Frame-Options: ALLOW-FROM {x_frame_options.split('allow-from ')[1]})",
                "MEDIUM",
                verify_cmd=f'Check manually by embedding {url} in an iframe from allowed origin.'
            )
            vulnerable = True
        else:
            safe("X-Frame-Options or Content-Security-Policy (frame-ancestors) headers are set, likely protecting against Clickjacking.")

    except Exception as e:
        log(f"[-] Error checking Clickjacking for {url}: {e}")

    if not vulnerable:
        safe("Clickjacking protection appears to be in place.")
