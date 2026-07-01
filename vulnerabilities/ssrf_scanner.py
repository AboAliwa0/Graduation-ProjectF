from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import os
from urllib.parse import quote

from services.oast import (
    OASTConfigurationError,
    cleanup,
    register,
    token_fingerprint,
    validate_callback_base_url,
    wait_for_hit,
)
from services.scan_runtime import current_runtime
from vulnerabilities.common import append_query_param, error_result, inconclusive, make_result, safe_request, unique_token

OBSERVATION_WINDOW_SECONDS = 3.0

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
    attempts = 0
    if not param:
        return inconclusive(
            "A URL parameter is required.",
            evidence={"callback_configured": False, "final_decision": "missing_parameter"},
            endpoint=url,
            requests_made=0,
        )
    configured_base = callback_base_url or os.getenv("OAST_PUBLIC_BASE_URL", "")
    if not configured_base:
        return inconclusive(
            "No callback base URL was configured, so SSRF cannot be confirmed reliably.",
            evidence={"callback_configured": False, "final_decision": "missing_callback_setup"},
            endpoint=url,
            parameter=param,
            recommendation="Configure OAST_PUBLIC_BASE_URL or provide the callback base field.",
            requests_made=0,
        )

    try:
        base = validate_callback_base_url(configured_base)
    except OASTConfigurationError:
        return inconclusive(
            "The callback base URL is invalid or blocked by the OAST safety policy.",
            evidence={"callback_configured": True, "final_decision": "invalid_or_blocked_callback"},
            endpoint=url,
            parameter=param,
            requests_made=0,
        )

    token = unique_token("ssrf")
    callback = f"{base.rstrip('/')}/oast/{quote(token)}"
    register(token)
    try:
        attempts += 1
        response = safe_request("GET", append_query_param(url, param, callback))
        hits = wait_for_hit(token, timeout=OBSERVATION_WINDOW_SECONDS)
        runtime = current_runtime()
        if runtime is not None and runtime.is_cancelled():
            raise ScanCancelled("Scan cancellation was requested.")
        evidence = {
            "token_hash": token_fingerprint(token),
            "callback_configured": True,
            "target_status": response.status_code,
            "callback_observed": bool(hits),
            "hit_count": len(hits),
            "observation_window_seconds": OBSERVATION_WINDOW_SECONDS,
        }
        if hits:
            evidence["final_decision"] = "confirmed_unique_callback_observed"
            return make_result(
                True,
                "The target server made a request to the unique CyberScan callback URL.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Use an outbound URL allowlist, block private/link-local networks after DNS resolution, and validate every redirect hop.",
                endpoint=url,
                parameter=param,
                cwe="CWE-918",
                cvss=9.1,
                requests_made=attempts,
            )
        evidence["external_setup_may_be_required"] = True
        evidence["final_decision"] = "callback_not_observed"
        return inconclusive(
            "No out-of-band callback was observed during the short verification window; SSRF safety was not confirmed.",
            severity="Info",
            confidence="Low",
            evidence=evidence,
            recommendation="Verify that the callback URL is externally reachable, then repeat or monitor for delayed callbacks.",
            endpoint=url,
            parameter=param,
            cwe="CWE-918",
            requests_made=attempts,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(
            "SSRF callback verification failed due to a transport or processing error.",
            evidence={
                "token_hash": token_fingerprint(token),
                "callback_configured": True,
                "error_type": type(exc).__name__,
                "final_decision": "transport_or_processing_error",
            },
            endpoint=url,
            parameter=param,
            requests_made=attempts,
        )
    finally:
        cleanup(token)
