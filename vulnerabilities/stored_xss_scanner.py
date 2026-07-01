import hashlib

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from bs4 import BeautifulSoup
from vulnerabilities.common import body_text, error_result, inconclusive, make_result, safe_request, unique_token

meta = {
    "name": "Stored XSS Verification",
    "severity": "Critical",
    "description": "Stores a harmless script marker through an explicitly configured test form and verifies it on a view page.",
    "category": "Injection",
}
inputs = [
    {"name": "submit_url", "label": "Submission URL", "type": "url", "required": True, "placeholder": "https://target.example/comment"},
    {"name": "view_url", "label": "View URL", "type": "url", "required": True, "placeholder": "https://target.example/comments"},
    {"name": "param_name", "label": "Content field", "type": "text", "required": True, "placeholder": "comment"},
]


def scan(url, submit_url="", view_url="", param_name=""):
    attempts = 0
    if not submit_url or not view_url or not param_name:
        return inconclusive(
            "Submission URL, view URL, and content field are all required.",
            evidence={"final_decision": "missing_required_inputs"},
            endpoint=url,
            requests_made=0,
        )
    token = unique_token("storedxss")
    payload = f"<script>window.__cyberscan_stored='{token}'</script>"
    marker_hash = f"sha256:{hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]}"
    try:
        attempts += 1
        submitted = safe_request("POST", submit_url, data={param_name: payload}, allow_redirects=True)
        if not 200 <= submitted.status_code < 300:
            return inconclusive(
                "The configured submission endpoint did not accept the harmless test marker successfully.",
                evidence={
                    "marker_hash": marker_hash,
                    "submit_status": submitted.status_code,
                    "view_status": None,
                    "final_decision": "submission_failed",
                },
                endpoint=submit_url,
                parameter=param_name,
                cwe="CWE-79",
                requests_made=attempts,
            )

        attempts += 1
        viewed = safe_request("GET", view_url)
        body = body_text(viewed)
        content_type = viewed.headers.get("Content-Type", "").lower()
        successful_html_view = 200 <= viewed.status_code < 300 and any(
            item in content_type for item in ("text/html", "application/xhtml+xml")
        )
        if not successful_html_view:
            return inconclusive(
                "The configured view endpoint did not return a successful HTML response.",
                evidence={
                    "marker_hash": marker_hash,
                    "submit_status": submitted.status_code,
                    "view_status": viewed.status_code,
                    "view_content_type": viewed.headers.get("Content-Type", ""),
                    "final_decision": "view_not_successful_html",
                },
                endpoint=view_url,
                parameter=param_name,
                cwe="CWE-79",
                requests_made=attempts,
            )

        soup = BeautifulSoup(body, "html.parser")
        script_node = soup.find("script", string=lambda value: bool(value and token in value)) if soup else None
        inert_context = script_node.find_parent(["textarea", "title", "style", "xmp", "noscript", "template"]) is not None if script_node else False
        confirmed = bool(script_node) and not inert_context
        evidence = {
            "marker_hash": marker_hash,
            "submit_status": submitted.status_code,
            "view_status": viewed.status_code,
            "exact_script_markup_stored": payload in body,
            "script_element_parsed": bool(script_node),
            "inert_html_context": inert_context,
        }
        if confirmed:
            evidence["final_decision"] = "confirmed_executable_stored_marker"
            return make_result(
                True,
                "Harmless script markup was stored and later returned unescaped in HTML.",
                severity="Critical",
                confidence="High",
                evidence=evidence,
                recommendation="Sanitize rich-text input, apply context-aware output encoding, and remove the test record after verification.",
                endpoint=viewed.url,
                parameter=param_name,
                cwe="CWE-79",
                cvss=9.0,
                requests_made=attempts,
            )
        evidence["final_decision"] = "executable_context_not_confirmed"
        return make_result(
            False,
            "The unique script marker was not returned unescaped from the configured view page.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=viewed.url,
            parameter=param_name,
            cwe="CWE-79",
            requests_made=attempts,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(
            f"Stored-XSS verification failed: {exc}",
            evidence={"final_decision": "transport_or_processing_error"},
            endpoint=url,
            parameter=param_name,
            requests_made=attempts,
        )
