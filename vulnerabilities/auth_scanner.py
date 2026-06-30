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
    {"name": "captcha_marker", "label": "CAPTCHA marker", "type": "text", "required": False, "placeholder": "CAPTCHA"},
    {"name": "lockout_marker", "label": "Lockout marker", "type": "text", "required": False, "placeholder": "Account locked"},
    {"name": "rate_limit_marker", "label": "Rate-limit marker", "type": "text", "required": False, "placeholder": "Too many attempts"},
]

MAX_ATTEMPTS = 5


def scan(
    url,
    login_url="",
    username_field="username",
    password_field="password",
    test_username="",
    failure_marker="",
    captcha_marker="",
    lockout_marker="",
    rate_limit_marker="",
):
    missing_inputs = []
    if not login_url:
        missing_inputs.append("login_url")
    if not test_username:
        missing_inputs.append("test_username")
    if not failure_marker:
        missing_inputs.append("failure_marker")
    if missing_inputs:
        return inconclusive(
            "Login URL, authorized test username, and normal failure marker are required.",
            evidence={"missing_inputs": missing_inputs, "attempt_count": 0},
            endpoint=login_url or url,
            requests_made=0,
        )

    observations = []
    requests_made = 0
    try:
        for index in range(MAX_ATTEMPTS):
            started = time.perf_counter()
            requests_made += 1
            response = safe_request(
                "POST",
                login_url,
                data={username_field or "username": test_username, password_field or "password": f"CyberScan-Wrong-{index}"},
                allow_redirects=False,
            )
            elapsed = time.perf_counter() - started
            response_text = body_text(response)
            retry_after_observed = bool(response.headers.get("Retry-After"))
            captcha_observed = bool(captcha_marker and captcha_marker in response_text)
            lockout_observed = bool(lockout_marker and lockout_marker in response_text)
            rate_limit_marker_observed = bool(rate_limit_marker and rate_limit_marker in response_text)
            observations.append({
                "attempt": index + 1,
                "status": response.status_code,
                "retry_after_observed": retry_after_observed,
                "elapsed": round(elapsed, 3),
                "failure_marker_seen": failure_marker in response_text,
                "captcha_observed": captcha_observed,
                "lockout_observed": lockout_observed,
                "rate_limit_marker_observed": rate_limit_marker_observed,
            })
            if (
                response.status_code == 429
                or retry_after_observed
                or captcha_observed
                or lockout_observed
                or rate_limit_marker_observed
            ):
                break
            time.sleep(0.08)

        throttling_observed = any(item["status"] == 429 for item in observations)
        retry_after_observed = any(item["retry_after_observed"] for item in observations)
        progressive_delay_observed = (
            len(observations) >= 3
            and observations[-1]["elapsed"] >= max(1.5, observations[0]["elapsed"] * 3)
        )
        captcha_observed = any(item["captcha_observed"] for item in observations)
        lockout_observed = any(item["lockout_observed"] for item in observations)
        rate_limit_marker_observed = any(item["rate_limit_marker_observed"] for item in observations)
        protection_observed = any((
            throttling_observed,
            retry_after_observed,
            progressive_delay_observed,
            captcha_observed,
            lockout_observed,
            rate_limit_marker_observed,
        ))
        ordinary_failures = [
            item for item in observations
            if not (
                item["status"] == 429
                or item["retry_after_observed"]
                or item["captcha_observed"]
                or item["lockout_observed"]
                or item["rate_limit_marker_observed"]
            )
        ]
        failure_evidence_consistent = (
            any(item["failure_marker_seen"] for item in observations)
            and all(item["failure_marker_seen"] for item in ordinary_failures)
        )
        evidence = {
            "attempt_count": len(observations),
            "max_attempts": MAX_ATTEMPTS,
            "throttling_observed": throttling_observed,
            "retry_after_observed": retry_after_observed,
            "progressive_delay_observed": progressive_delay_observed,
            "captcha_observed": captcha_observed,
            "lockout_observed": lockout_observed,
            "rate_limit_marker_observed": rate_limit_marker_observed,
            "failure_evidence_consistent": failure_evidence_consistent,
            "attempts": observations,
        }

        if not failure_evidence_consistent:
            return inconclusive(
                "The expected normal failure marker was not observed consistently, so failed login attempts could not be verified.",
                evidence=evidence,
                endpoint=login_url,
                cwe="CWE-307",
                requests_made=requests_made,
            )

        if protection_observed:
            return make_result(
                False,
                "Observable throttling, CAPTCHA, lockout, rate-limit messaging, or progressive delay was detected.",
                severity="Info",
                confidence="High" if (throttling_observed or retry_after_observed or lockout_observed) else "Medium",
                evidence=evidence,
                endpoint=login_url,
                cwe="CWE-307",
                requests_made=requests_made,
            )

        if len(observations) < MAX_ATTEMPTS:
            return inconclusive(
                "The five authorized failed login attempts did not complete, so login-abuse protection could not be assessed.",
                evidence=evidence,
                endpoint=login_url,
                cwe="CWE-307",
                requests_made=requests_made,
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
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Login-abuse protection check failed: {exc}", endpoint=login_url or url, requests_made=requests_made)
