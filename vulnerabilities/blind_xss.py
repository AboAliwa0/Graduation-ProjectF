from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import os
from urllib.parse import quote

from services.oast import cleanup, register, wait_for_hit
from vulnerabilities.common import append_query_param, error_result, inconclusive, make_result, safe_request, unique_token

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
    if not param:
        return inconclusive("A parameter is required.", endpoint=url)
    base = callback_base_url or os.getenv("OAST_PUBLIC_BASE_URL", "")
    if not base:
        return inconclusive(
            "Blind XSS requires an observable callback endpoint; no callback base URL was configured.",
            endpoint=url,
            parameter=param,
        )

    token = unique_token("blindxss")
    callback = f"{base.rstrip('/')}/oast/{quote(token)}"
    payload = f'<script src="{callback}"></script>'
    register(token)
    try:
        response = safe_request("GET", append_query_param(url, param, payload))
        hits = wait_for_hit(token, timeout=4.0)
        evidence = {"callback": callback, "submission_status": response.status_code, "callback_hits": hits}
        if hits:
            return make_result(
                True,
                "The unique blind-XSS callback was requested after payload submission.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Sanitize stored input, contextually encode output, and deploy a strict Content Security Policy.",
                endpoint=response.url,
                parameter=param,
                cwe="CWE-79",
                cvss=8.7,
                requests_made=1,
            )
        return inconclusive(
            "The payload was submitted, but no callback was observed during the short verification window.",
            evidence=evidence,
            endpoint=response.url,
            parameter=param,
            cwe="CWE-79",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Blind-XSS check failed: {exc}", endpoint=url, parameter=param)
    finally:
        cleanup(token)
