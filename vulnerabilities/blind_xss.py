from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import os
from urllib.parse import quote, urlencode

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

OBSERVATION_WINDOW_SECONDS = 4.0

meta = {
    "name": "Blind XSS Callback",
    "severity": "High",
    "description": "Sends a harmless unique callback script and reports a vulnerability only when the callback is observed.",
    "category": "Injection",
}
inputs = [
    {"name": "param", "label": "Parameter", "type": "text", "required": True, "placeholder": "message"},
    {"name": "callback_base_url", "label": "CyberScan public callback base", "type": "url", "required": False, "placeholder": "https://scanner.example"},
]


def scan(url, param="", callback_base_url=""):
    attempts = 0
    if not param:
        return inconclusive(
            "A parameter is required.",
            evidence={"callback_configured": False, "final_decision": "missing_parameter"},
            endpoint=url,
            requests_made=0,
        )
    configured_base = callback_base_url or os.getenv("OAST_PUBLIC_BASE_URL", "")
    if not configured_base:
        return inconclusive(
            "Blind XSS requires an observable callback endpoint; no callback base URL was configured.",
            evidence={"callback_configured": False, "final_decision": "missing_callback_setup"},
            endpoint=url,
            parameter=param,
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

    fetch_token = unique_token("blindxss-fetch")
    execution_token = unique_token("blindxss-exec")
    callback = f"{base.rstrip('/')}/oast/{quote(fetch_token)}?{urlencode({'execution': execution_token})}"
    payload = f'<script src="{callback}"></script>'
    register(fetch_token)
    register(execution_token)
    try:
        attempts += 1
        response = safe_request("GET", append_query_param(url, param, payload))
        execution_hits = wait_for_hit(execution_token, timeout=OBSERVATION_WINDOW_SECONDS)
        fetch_hits = wait_for_hit(fetch_token, timeout=0)
        runtime = current_runtime()
        if runtime is not None and runtime.is_cancelled():
            raise ScanCancelled("Scan cancellation was requested.")
        evidence = {
            "token_hash": token_fingerprint(execution_token),
            "callback_configured": True,
            "submission_status": response.status_code,
            "script_fetch_observed": bool(fetch_hits),
            "execution_beacon_observed": bool(execution_hits),
            "script_fetch_count": len(fetch_hits),
            "execution_beacon_count": len(execution_hits),
            "observation_window_seconds": OBSERVATION_WINDOW_SECONDS,
        }
        if execution_hits:
            evidence["final_decision"] = "confirmed_browser_execution_beacon"
            return make_result(
                True,
                "The harmless callback script executed and sent the unique execution beacon.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Sanitize stored input, contextually encode output, and deploy a strict Content Security Policy.",
                endpoint=url,
                parameter=param,
                cwe="CWE-79",
                cvss=8.7,
                requests_made=attempts,
            )

        if fetch_hits:
            evidence["final_decision"] = "script_fetched_without_execution_proof"
            return make_result(
                True,
                "The callback script was fetched, but browser execution was not proven. Manual validation is required.",
                severity="Medium",
                confidence="Low",
                status="potential",
                evidence=evidence,
                recommendation="Verify the rendering context manually and sanitize stored input with context-aware output encoding.",
                endpoint=url,
                parameter=param,
                cwe="CWE-79",
                cvss=5.4,
                requests_made=attempts,
            )

        evidence["final_decision"] = "callback_not_observed"
        return inconclusive(
            "The payload was submitted, but no callback was observed during the short verification window.",
            evidence=evidence,
            endpoint=url,
            parameter=param,
            cwe="CWE-79",
            requests_made=attempts,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(
            "Blind-XSS callback verification failed due to a transport or processing error.",
            evidence={
                "token_hash": token_fingerprint(execution_token),
                "callback_configured": True,
                "error_type": type(exc).__name__,
                "final_decision": "transport_or_processing_error",
            },
            endpoint=url,
            parameter=param,
            requests_made=attempts,
        )
    finally:
        cleanup(fetch_token)
        cleanup(execution_token)
