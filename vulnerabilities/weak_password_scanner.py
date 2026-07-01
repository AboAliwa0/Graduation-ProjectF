import hashlib
from urllib.parse import urljoin, urlparse

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
    attempts = 0
    if not login_url or not test_username or not test_password:
        return inconclusive(
            "Login URL and one authorized test credential are required.",
            evidence={"final_decision": "missing_required_inputs"},
            endpoint=url,
            requests_made=0,
        )
    if not success_marker and not success_redirect_contains:
        return inconclusive(
            "A success marker or expected success redirect is required to avoid treating a rejected password as accepted.",
            evidence={"final_decision": "missing_success_criterion"},
            endpoint=login_url,
            requests_made=0,
        )
    try:
        attempts += 1
        response = safe_request(
            "POST",
            login_url,
            data={username_field or "username": test_username, password_field or "password": test_password},
            allow_redirects=False,
        )
        body = body_text(response)
        location = response.headers.get("Location", "")
        successful_status = 200 <= response.status_code < 300
        redirect_status = 300 <= response.status_code < 400
        marker_present = bool(success_marker and success_marker in body)
        marker_ok = successful_status and marker_present
        redirect_ok = bool(redirect_status and location and success_redirect_contains and success_redirect_contains in location)
        redirect_path = urlparse(urljoin(login_url, location)).path if location else ""
        redirect_path_hash = (
            f"sha256:{hashlib.sha256(redirect_path.encode('utf-8')).hexdigest()[:12]}"
            if redirect_path
            else ""
        )
        evidence = {
            "status_code": response.status_code,
            "successful_status": successful_status,
            "redirect_status": redirect_status,
            "redirect_path_hash": redirect_path_hash,
            "success_marker_present": marker_present,
            "success_marker_matched": marker_ok,
            "success_redirect_matched": redirect_ok,
            "credential_count": 1,
        }
        if marker_ok or redirect_ok:
            evidence["final_decision"] = "credential_acceptance_confirmed"
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
                requests_made=attempts,
            )

        if response.status_code in {401, 403}:
            evidence["final_decision"] = "credential_rejected"
            return make_result(
                False,
                "The supplied weak test credential was rejected by the login endpoint.",
                severity="Info",
                confidence="High",
                evidence=evidence,
                endpoint=login_url,
                cwe="CWE-521",
                requests_made=attempts,
            )

        evidence["final_decision"] = "success_criterion_not_observed"
        return inconclusive(
            "The response did not reliably prove either credential acceptance or rejection.",
            evidence=evidence,
            endpoint=login_url,
            cwe="CWE-521",
            requests_made=attempts,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(
            f"Weak-credential verification failed: {exc}",
            evidence={"credential_count": 1, "final_decision": "transport_or_processing_error"},
            endpoint=login_url or url,
            requests_made=attempts,
        )
