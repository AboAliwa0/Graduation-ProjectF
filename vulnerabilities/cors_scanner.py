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
    protected_cache_policy = "private" in cache_control or "no-store" in cache_control
    clearly_protected = authenticated_request or protected_cache_policy
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "vary_origin": "origin" in {
            item.strip().lower() for item in response.headers.get("Vary", "").split(",") if item.strip()
        },
        "vary": response.headers.get("Vary", ""),
        "authenticated_request": authenticated_request,
        "clearly_protected": clearly_protected,
        "protected_cache_policy": protected_cache_policy,
        "sensitive_markers": sensitive_markers,
    }


def scan(url):
    findings = []
    requests_made = 0
    try:
        for origin in TEST_ORIGINS:
            requests_made += 1
            response = safe_request("GET", url, headers={"Origin": origin})
            allow_origin = response.headers.get("Access-Control-Allow-Origin", "").strip()
            credentials = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
            context = _response_context(response)
            sensitive_or_protected = context["authenticated_request"] or (
                context["protected_cache_policy"] and bool(context["sensitive_markers"])
            )
            strong_risk = (
                credentials
                and 200 <= response.status_code < 300
                and sensitive_or_protected
            )

            observation = {
                "issue": "none",
                "origin": origin,
                "allow_origin": allow_origin or "missing",
                "credentials": credentials,
                "vary": context["vary"],
                "vary_origin": context["vary_origin"],
                "severity": "Info",
                "classification": "informational",
                "context": context,
            }
            if allow_origin == origin:
                observation.update({
                    "issue": "null_origin_allowed" if origin == "null" else "arbitrary_origin_reflection",
                    "severity": "High" if strong_risk else "Medium",
                    "classification": "confirmed" if strong_risk else "potential",
                })
            elif allow_origin == "*" and credentials:
                # Browsers reject wildcard + credentials, so this is a bad policy but not
                # the same as credentialed arbitrary-origin access.
                observation.update({
                    "issue": "invalid_wildcard_credentials_combination",
                    "severity": "Low",
                    "classification": "informational",
                })
            findings.append(observation)

        preflight_origin = TEST_ORIGINS[0]
        requests_made += 1
        preflight = safe_request(
            "OPTIONS",
            url,
            headers={
                "Origin": preflight_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        preflight_allow = preflight.headers.get("Access-Control-Allow-Origin", "").strip()
        preflight_creds = preflight.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        preflight_context = _response_context(preflight)
        preflight_successful = 200 <= preflight.status_code < 300
        preflight_reflected = preflight_allow == preflight_origin
        findings.append({
            "issue": "preflight_allows_arbitrary_origin" if preflight_successful and preflight_reflected else "preflight_not_permissive",
            "origin": preflight_origin,
            "credentials": preflight_creds,
            "severity": "High" if preflight_successful and preflight_reflected and preflight_creds else ("Medium" if preflight_successful and preflight_reflected else "Info"),
            "classification": "potential" if preflight_successful and preflight_reflected else "informational",
            "status_code": preflight.status_code,
            "allow_origin": preflight_allow or "missing",
            "vary": preflight_context["vary"],
            "vary_origin": preflight_context["vary_origin"],
            "context": preflight_context,
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

        informational = [item for item in findings if item["classification"] == "informational" and item["issue"] != "none"]
        message = (
            "CORS policy observations were recorded, but no browser-exploitable cross-origin access was confirmed."
            if informational
            else "No arbitrary-origin CORS behavior was detected."
        )
        return make_result(
            False,
            message,
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
