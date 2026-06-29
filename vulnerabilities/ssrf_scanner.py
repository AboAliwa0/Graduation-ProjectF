from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import os
from urllib.parse import quote

from services.oast import cleanup, register, wait_for_hit
from vulnerabilities.common import append_query_param, error_result, inconclusive, make_result, safe_request, unique_token

meta = {
    "name": "SSRF Callback Verification",
    "severity": "High",
    "description": "Uses a unique out-of-band callback token; reflected URLs alone are never treated as SSRF.",
    "category": "Server-Side Request Forgery",
}
inputs = [
    {"name": "param", "label": "URL parameter", "type": "text", "required": True, "placeholder": "url"},
    {"name": "callback_base_url", "label": "CyberScan public callback base", "type": "url", "required": False, "placeholder": "https://scanner.example", "help": "Must be reachable by the target. In a local lab use the local CyberScan URL."},
]


def scan(url, param="", callback_base_url=""):
    if not param:
        return inconclusive("A URL parameter is required.", endpoint=url)
    base = callback_base_url or os.getenv("OAST_PUBLIC_BASE_URL", "")
    if not base:
        return inconclusive(
            "No callback base URL was configured, so SSRF cannot be confirmed reliably.",
            endpoint=url,
            parameter=param,
            recommendation="Configure OAST_PUBLIC_BASE_URL or provide the callback base field.",
        )

    token = unique_token("ssrf")
    callback = f"{base.rstrip('/')}/oast/{quote(token)}"
    register(token)
    try:
        response = safe_request("GET", append_query_param(url, param, callback))
        hits = wait_for_hit(token, timeout=3.0)
        evidence = {
            "callback": callback,
            "target_status": response.status_code,
            "callback_hits": hits,
            "callback_observed": bool(hits),
            "verification_window_seconds": 3.0,
        }
        if hits:
            return make_result(
                True,
                "The target server made a request to the unique CyberScan callback URL.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Use an outbound URL allowlist, block private/link-local networks after DNS resolution, and validate every redirect hop.",
                endpoint=response.url,
                parameter=param,
                cwe="CWE-918",
                cvss=9.1,
                requests_made=1,
            )
        evidence["external_setup_may_be_required"] = True
        return inconclusive(
            "No out-of-band callback was observed during the short verification window; SSRF safety was not confirmed.",
            severity="Info",
            confidence="Low",
            evidence=evidence,
            recommendation="Verify that the callback URL is externally reachable, then repeat or monitor for delayed callbacks.",
            endpoint=response.url,
            parameter=param,
            cwe="CWE-918",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"SSRF callback check failed: {exc}", endpoint=url, parameter=param)
    finally:
        cleanup(token)
