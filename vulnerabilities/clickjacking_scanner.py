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
    requests_made = 0
    try:
        requests_made = 1
        response = safe_request("GET", url)
        content_type = response.headers.get("Content-Type", "").lower()
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
            "content_type": response.headers.get("Content-Type", ""),
        }

        successful_html = 200 <= response.status_code < 300 and any(
            value in content_type for value in ("text/html", "application/xhtml+xml")
        )
        if not successful_html:
            return make_result(
                False,
                "Clickjacking protection was not assessed because the target was not a successful HTML page.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                evidence=evidence,
                endpoint=response.url,
                cwe="CWE-1021",
                requests_made=requests_made,
            )

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
        return error_result(f"Clickjacking check failed: {exc}", endpoint=url, requests_made=requests_made)
