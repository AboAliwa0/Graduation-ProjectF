from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from vulnerabilities.common import body_text, error_result, inconclusive, make_result, safe_request

meta = {
    "name": "Known Weak Test Credential",
    "severity": "High",
    "description": "Verifies one explicitly supplied test credential; it does not use dictionaries or brute force.",
    "category": "Authentication",
}
inputs = [
    {"name": "login_url", "label": "Login URL", "type": "url", "required": True, "placeholder": "https://target.example/login"},
    {"name": "username_field", "label": "Username field", "type": "text", "required": False, "placeholder": "username"},
    {"name": "password_field", "label": "Password field", "type": "text", "required": False, "placeholder": "password"},
    {"name": "test_username", "label": "Authorized test username", "type": "text", "required": True, "placeholder": "test-user"},
    {"name": "test_password", "label": "Weak password to verify", "type": "password", "required": True, "placeholder": "Password1"},
    {"name": "success_marker", "label": "Success response marker", "type": "text", "required": False, "placeholder": "Welcome"},
    {"name": "success_redirect_contains", "label": "Success redirect contains", "type": "text", "required": False, "placeholder": "/dashboard"},
]


def scan(url, login_url="", username_field="username", password_field="password", test_username="", test_password="", success_marker="", success_redirect_contains=""):
    if not login_url or not test_username or not test_password:
        return inconclusive("Login URL and one authorized test credential are required.", endpoint=url)
    if not success_marker and not success_redirect_contains:
        return inconclusive(
            "A success marker or expected success redirect is required to avoid treating a rejected password as accepted.",
            endpoint=login_url,
        )
    try:
        response = safe_request(
            "POST",
            login_url,
            data={username_field or "username": test_username, password_field or "password": test_password},
            allow_redirects=False,
        )
        body = body_text(response)
        location = response.headers.get("Location", "")
        marker_ok = bool(success_marker and success_marker in body)
        redirect_ok = bool(success_redirect_contains and success_redirect_contains in location)
        evidence = {
            "status_code": response.status_code,
            "location": location,
            "success_marker_matched": marker_ok,
            "success_redirect_matched": redirect_ok,
            "username": test_username,
        }
        if marker_ok or redirect_ok:
            return make_result(
                True,
                "The explicitly supplied weak test credential was accepted.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Enforce a strong password policy, block common passwords, enable MFA, and require the test account password to be changed.",
                endpoint=login_url,
                cwe="CWE-521",
                cvss=8.8,
                requests_made=1,
            )
        return make_result(
            False,
            "The supplied weak test credential was not accepted according to the configured success criterion.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=login_url,
            cwe="CWE-521",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Weak-credential verification failed: {exc}", endpoint=login_url or url)
