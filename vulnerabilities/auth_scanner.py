from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import time

from vulnerabilities.common import body_text, error_result, inconclusive, make_result, safe_request

meta = {
    "name": "Login Abuse Protection",
    "severity": "Medium",
    "description": "Performs five authorized failed login attempts and observes rate-limit or lockout signals.",
    "category": "Authentication",
}
inputs = [
    {"name": "login_url", "label": "Login URL", "type": "url", "required": True, "placeholder": "https://target.example/login"},
    {"name": "username_field", "label": "Username field", "type": "text", "required": False, "placeholder": "username"},
    {"name": "password_field", "label": "Password field", "type": "text", "required": False, "placeholder": "password"},
    {"name": "test_username", "label": "Authorized test username", "type": "text", "required": True, "placeholder": "security-test"},
    {"name": "failure_marker", "label": "Normal failure marker", "type": "text", "required": False, "placeholder": "Invalid credentials"},
]

MAX_ATTEMPTS = 5


def scan(url, login_url="", username_field="username", password_field="password", test_username="", failure_marker=""):
    if not login_url or not test_username:
        return inconclusive("Login URL and an authorized test username are required.", endpoint=url)
    observations = []
    try:
        for index in range(MAX_ATTEMPTS):
            started = time.perf_counter()
            response = safe_request(
                "POST",
                login_url,
                data={username_field or "username": test_username, password_field or "password": f"CyberScan-Wrong-{index}"},
                allow_redirects=False,
            )
            elapsed = time.perf_counter() - started
            observations.append({
                "attempt": index + 1,
                "status": response.status_code,
                "retry_after": response.headers.get("Retry-After", ""),
                "elapsed": round(elapsed, 3),
                "failure_marker_seen": bool(failure_marker and failure_marker in body_text(response)),
            })
            if response.status_code == 429 or response.headers.get("Retry-After"):
                break
            time.sleep(0.08)

        protected = any(item["status"] == 429 or item["retry_after"] for item in observations)
        delayed = len(observations) >= 3 and observations[-1]["elapsed"] >= max(1.5, observations[0]["elapsed"] * 3)
        evidence = {"attempts": observations, "max_attempts": MAX_ATTEMPTS}
        if protected or delayed:
            return make_result(
                False,
                "Observable throttling, lockout, or progressive delay was detected.",
                severity="Info",
                confidence="High" if protected else "Medium",
                evidence=evidence,
                endpoint=login_url,
                cwe="CWE-307",
                requests_made=len(observations),
            )

        return make_result(
            True,
            "No observable throttling was triggered during five failed attempts. This is a potential weakness, not proof of unlimited brute force.",
            severity="Medium",
            confidence="Low",
            status="potential",
            evidence=evidence,
            recommendation="Add per-account and per-IP throttling, progressive delays, monitoring, and MFA.",
            endpoint=login_url,
            cwe="CWE-307",
            cvss=5.3,
            requests_made=len(observations),
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Login-abuse protection check failed: {exc}", endpoint=login_url or url, requests_made=len(observations))
