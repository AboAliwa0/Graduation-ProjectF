import re
import time
import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Weak Password / Brute Force",
    "severity": "Critical",
    "description": "Tests login security (weak passwords, brute-force, lockout, rate limiting)"
}

inputs = ["login_url", "username_field", "password_field"]


# -----------------------
# 🧠 HELPERS
# -----------------------

def is_strong(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password)
    )


def detect_rate_limit(times):
    if len(times) < 5:
        return False
    return sum(times[-3:]) > sum(times[:3]) * 1.5


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, login_url=None, username_field="username", password_field="password"):
    if not login_url:
        return {
            "vulnerable": False,
            "result": "Login URL not provided",
            "severity": "Low"
        }

    session = requests.Session()

    usernames = ["admin", "test"]
    passwords = ["admin", "123456", "password", "Admin123!"]

    response_times = []
    findings = []

    try:
        for user in usernames:
            for pwd in passwords:

                data = {username_field: user, password_field: pwd}

                start = time.time()
                r = session.post(login_url, data=data, timeout=10)
                elapsed = time.time() - start

                response_times.append(elapsed)
                text = r.text.lower()

                # 🔥 successful login
                if any(k in text for k in ["dashboard", "welcome", "logout"]):
                    findings.append(f"Valid credentials found: {user}/{pwd}")
                    break

                # 🔥 weak password
                if not is_strong(pwd):
                    findings.append(f"Weak password tested: {pwd}")

            if findings:
                break

        # 🔥 rate limiting
        if not detect_rate_limit(response_times):
            findings.append("No rate limiting detected")

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if findings:
            return {
                "vulnerable": True,
                "result": " | ".join(findings),
                "severity": "Critical"
            }

        return {
            "vulnerable": False,
            "result": "No weak password issues detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }