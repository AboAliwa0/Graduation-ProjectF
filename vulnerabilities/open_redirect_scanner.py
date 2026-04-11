from utils import get_session, rate_sleep
from report import section, vuln, safe, log

def check_open_redirect(url):
    section("Open Redirect")
    session = get_session()
    vulnerable = False

    # A list of common redirect parameters and malicious URLs
    redirect_params = [
        "next", "url", "target", "redirect", "redir", "return", "continue",
        "dest", "destination", "path", "uri", "view", "checkout", "return_to"
    ]
    malicious_url = "http://evil.com/redirect_test"

    log(f"[*] Testing for Open Redirect on: {url}")

    for param in redirect_params:
        test_url = f"{url}?{param}={malicious_url}"
        try:
            rate_sleep()
            # Allow redirects to check if it goes to the malicious URL
            r = session.get(test_url, allow_redirects=True, timeout=10)

            # Check if the final URL after redirection is the malicious one
            if r.url == malicious_url:
                vuln(
                    f"Open Redirect vulnerability detected via parameter \'{param}\'",
                    "HIGH",
                    verify_cmd=f"curl -L \"{test_url}\""
                )
                vulnerable = True
                break # Found one, no need to test other parameters
            else:
                log(f"[*] Parameter \'{param}\' did not lead to open redirect. Final URL: {r.url}")

        except Exception as e:
            log(f"[-] Error testing Open Redirect with parameter \'{param}\' for {url}: {e}")

    if not vulnerable:
        safe("Open Redirect protection appears to be in place or no vulnerable parameters found.")
