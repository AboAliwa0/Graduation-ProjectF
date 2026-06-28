from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from vulnerabilities.common import error_result, make_result, safe_request

meta = {
    "name": "Clickjacking Protection",
    "severity": "Medium",
    "description": "Validates X-Frame-Options and CSP frame-ancestors directives.",
    "category": "Security Headers",
}
inputs = []


def scan(url):
    try:
        response = safe_request("GET", url)
        xfo = response.headers.get("X-Frame-Options", "").strip()
        csp = response.headers.get("Content-Security-Policy", "")
        xfo_value = xfo.upper()
        csp_lower = csp.lower()

        valid_xfo = xfo_value in {"DENY", "SAMEORIGIN"}
        has_frame_ancestors = "frame-ancestors" in csp_lower
        weak_xfo = bool(xfo) and not valid_xfo

        evidence = {
            "x_frame_options": xfo or "missing",
            "content_security_policy": csp or "missing",
            "status_code": response.status_code,
        }

        if not valid_xfo and not has_frame_ancestors:
            message = "The page has no effective X-Frame-Options or CSP frame-ancestors protection."
            if weak_xfo:
                message += " The supplied X-Frame-Options value is not broadly supported or valid."
            return make_result(
                True,
                message,
                severity="Medium",
                confidence="High",
                evidence=evidence,
                recommendation="Set CSP frame-ancestors and, for legacy clients, X-Frame-Options: DENY or SAMEORIGIN.",
                endpoint=response.url,
                cwe="CWE-1021",
                cvss=4.3,
                requests_made=1,
            )

        return make_result(
            False,
            "Effective anti-framing protection was detected.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=response.url,
            cwe="CWE-1021",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Clickjacking check failed: {exc}", endpoint=url)
