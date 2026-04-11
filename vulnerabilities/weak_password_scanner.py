import re
import time
from utils import get_session, rate_sleep
from report import section, vuln, safe, log


def load_file(filename, fallback):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return fallback


def is_strong_password(password):
    return (
        len(password) >= 8 and
        bool(re.search(r"[A-Z]", password)) and
        bool(re.search(r"[a-z]", password)) and
        bool(re.search(r"\d", password)) and
        bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    )


def detect_rate_limiting(times):
    if len(times) < 5:
        return False
    avg   = sum(times) / len(times)
    early = sum(times[:3]) / 3
    late  = sum(times[-3:]) / 3
    return late > early * 1.5 and avg > 1.0


def check_weak_password(url, user_field, pass_field):
    section("Login Security Analysis")

    session   = get_session()
    usernames = load_file("usernames.txt", ["admin"])
    passwords = load_file("passwords.txt", ["admin123", "123456", "password"])

    weak   = [p for p in passwords if not is_strong_password(p)]
    strong = [p for p in passwords if is_strong_password(p)]
    log(f"[*] {len(usernames)} usernames | {len(weak)} weak / {len(strong)} strong passwords loaded")

    LOCKOUT_KEYWORDS = [
        "locked", "temporarily blocked",
        "account disabled", "too many attempts",
        "temporarily disabled",
    ]
    SUCCESS_KEYWORDS = ["welcome", "dashboard", "logout", "my account", "profile"]

    response_times = []
    vulnerable     = False
    success_found  = False

    for user in usernames:
        for pwd in passwords:

            data = {user_field: user, pass_field: pwd}

            try:
                rate_sleep()
                start   = time.time()
                r       = session.post(url, data=data, timeout=10)
                elapsed = time.time() - start
                response_times.append(elapsed)

                response_text = r.text.lower()
                log(f"[*] {user}/{pwd} | {elapsed:.2f}s | Status: {r.status_code}")

                # 1. Account Lockout
                if any(k in response_text for k in LOCKOUT_KEYWORDS):
                    vuln(f"Account lockout detected for user: {user}", "HIGH")
                    vulnerable = True
                    break

                # 2. Successful Login
                if any(k in response_text for k in SUCCESS_KEYWORDS):
                    vuln(
                        f"Successful login: {user} / {pwd}",
                        "CRITICAL",
                        verify_cmd=f'curl -X POST -d "{user_field}={user}&{pass_field}={pwd}" {url}'
                    )
                    success_found = True
                    break

                # 3. Rate Limiting
                if detect_rate_limiting(response_times):
                    vuln("Rate limiting detected (brute-force protection active)", "INFO")
                    break

            except Exception as e:
                log(f"[-] Request error ({user}/{pwd}): {e}")

        if success_found:
            break

    if not vulnerable:
        safe("No account lockout mechanism detected")
    if not detect_rate_limiting(response_times):
        safe("No strong rate limiting detected")
    if not success_found:
        safe("No successful login indicator found")
