import re

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from vulnerabilities.common import body_text, error_result, highest_severity, make_result, safe_request

meta = {
    "name": "CORS Misconfiguration",
    "severity": "High",
    "description": "Checks arbitrary-origin reflection, null origins, credentials, and preflight behavior.",
    "category": "Security Configuration",
}
inputs = []

TEST_ORIGINS = ("https://cyberscan.invalid", "null")
SENSITIVE_MARKERS = re.compile(
    r'\b(private|confidential|account|profile|email|user[_ -]?id|balance|admin|access[_ -]?token|session)\b',
    re.I,
)


def _response_context(response):
    body = body_text(response)
    request_headers = getattr(getattr(response, "request", None), "headers", {}) or {}
    cache_control = response.headers.get("Cache-Control", "").lower()
    authenticated_request = bool(request_headers.get("Authorization") or request_headers.get("Cookie"))
    sensitive_markers = sorted({match.group(0).lower() for match in SENSITIVE_MARKERS.finditer(body[:200_000])})[:20]
    clearly_protected = authenticated_request or "private" in cache_control or "no-store" in cache_control
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "authenticated_request": authenticated_request,
        "clearly_protected": clearly_protected,
        "sensitive_markers": sensitive_markers,
    }


def scan(url):
    findings = []
    requests_made = 0
    try:
        for origin in TEST_ORIGINS:
            response = safe_request("GET", url, headers={"Origin": origin})
            requests_made += 1
            allow_origin = response.headers.get("Access-Control-Allow-Origin", "").strip()
            credentials = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            context = _response_context(response)
            strong_risk = (
                credentials
                and 200 <= response.status_code < 300
                and (context["clearly_protected"] or bool(context["sensitive_markers"]))
            )

            if allow_origin == origin:
                findings.append({
                    "issue": "null_origin_allowed" if origin == "null" else "arbitrary_origin_reflection",
                    "origin": origin,
                    "allow_origin": allow_origin,
                    "credentials": credentials,
                    "severity": "High" if strong_risk else "Medium",
                    "classification": "confirmed" if strong_risk else "potential",
                    "context": context,
                })
            elif allow_origin == "*" and credentials:
                # Browsers reject wildcard + credentials, so this is a bad policy but not
                # the same as credentialed arbitrary-origin access.
                findings.append({
                    "issue": "invalid_wildcard_credentials_combination",
                    "origin": origin,
                    "credentials": True,
                    "severity": "Low",
                    "classification": "informational",
                    "context": context,
                })

        preflight_origin = TEST_ORIGINS[0]
        preflight = safe_request(
            "OPTIONS",
            url,
            headers={
                "Origin": preflight_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        requests_made += 1
        preflight_allow = preflight.headers.get("Access-Control-Allow-Origin", "").strip()
        preflight_creds = preflight.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        if preflight_allow == preflight_origin:
            findings.append({
                "issue": "preflight_allows_arbitrary_origin",
                "origin": preflight_origin,
                "credentials": preflight_creds,
                "severity": "High" if preflight_creds else "Medium",
                "classification": "potential",
                "status_code": preflight.status_code,
                "allow_origin": preflight_allow,
            })

        confirmed = [item for item in findings if item["classification"] == "confirmed"]
        potential = [item for item in findings if item["classification"] == "potential"]
        if confirmed:
            return make_result(
                True,
                "Credentialed cross-origin access was confirmed for an unsafe origin on a sensitive or protected-looking response.",
                severity=highest_severity(item["severity"] for item in confirmed),
                confidence="High",
                status="confirmed",
                evidence={"classification_reason": "Unsafe origin behavior, credentials, and sensitive/protected response context were all observed.", "observations": findings},
                recommendation="Use a strict origin allowlist, never reflect untrusted origins, and enable credentials only for trusted origins.",
                endpoint=url,
                cwe="CWE-942",
                cvss=8.1,
                requests_made=requests_made,
            )

        if potential:
            return make_result(
                True,
                "Unsafe-looking CORS behavior was observed, but credentialed access to sensitive or protected content was not confirmed.",
                severity=highest_severity(item["severity"] for item in potential),
                confidence="Medium",
                status="potential",
                evidence={"classification_reason": "Origin reflection or permissive preflight was observed without enough evidence for confirmed browser-relevant impact.", "observations": findings},
                recommendation="Review whether the affected response is public. Use a strict origin allowlist and enable credentials only for trusted origins.",
                endpoint=url,
                cwe="CWE-942",
                cvss=5.3,
                requests_made=requests_made,
            )

        return make_result(
            False,
            "No arbitrary-origin CORS behavior was detected.",
            severity="Info",
            confidence="High",
            evidence={"tested_origins": list(TEST_ORIGINS), "observations": findings},
            endpoint=url,
            cwe="CWE-942",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"CORS check failed: {exc}", endpoint=url, requests_made=requests_made)
