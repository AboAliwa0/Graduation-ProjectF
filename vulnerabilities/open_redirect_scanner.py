from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from urllib.parse import urljoin, urlparse

from vulnerabilities.common import append_query_param, error_result, make_result, safe_request, unique_token

meta = {
    "name": "Open Redirect",
    "severity": "Medium",
    "description": "Tests a nominated redirect parameter without following the external destination.",
    "category": "Input Validation",
}
inputs = [
    {
        "name": "param",
        "label": "Redirect parameter",
        "type": "text",
        "required": True,
        "placeholder": "next",
        "help": "Example: next, return, redirect_uri.",
    }
]


def scan(url, param=""):
    if not param:
        return make_result(False, "A redirect parameter is required.", status="inconclusive", confidence="Low", endpoint=url)
    token = unique_token("redirect")
    destination = f"https://{token}.invalid/"
    candidate = append_query_param(url, param, destination)
    try:
        response = safe_request("GET", candidate, allow_redirects=False)
        location = response.headers.get("Location", "")
        resolved = urljoin(response.url, location) if location else ""
        host = urlparse(resolved).hostname or ""
        confirmed = response.status_code in {301, 302, 303, 307, 308} and host == f"{token}.invalid"
        evidence = {
            "status_code": response.status_code,
            "location": location,
            "resolved_location": resolved,
            "parameter": param,
        }
        if confirmed:
            return make_result(
                True,
                "The application redirected to an attacker-controlled external origin.",
                severity="Medium",
                confidence="High",
                evidence=evidence,
                recommendation="Allow only relative paths or validate redirect destinations against a strict host allowlist.",
                endpoint=response.url,
                parameter=param,
                cwe="CWE-601",
                cvss=6.1,
                requests_made=1,
            )
        return make_result(
            False,
            "No external redirect was confirmed for the supplied parameter.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=response.url,
            parameter=param,
            cwe="CWE-601",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Open-redirect check failed: {exc}", endpoint=url, parameter=param)
