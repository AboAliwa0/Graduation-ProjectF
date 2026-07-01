from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import json
import hashlib
import re
from urllib.parse import urljoin, urlparse

from vulnerabilities.common import body_text, error_result, inconclusive, make_result, safe_request, unique_token

meta = {
    "name": "Unsafe File Upload",
    "severity": "High",
    "description": "Uploads a harmless HTML marker and confirms whether it is publicly retrievable as active content.",
    "category": "File Handling",
}
inputs = [
    {"name": "upload_url", "label": "Upload URL", "type": "url", "required": True, "placeholder": "https://target.example/upload"},
    {"name": "file_field", "label": "File field", "type": "text", "required": True, "placeholder": "file"},
    {"name": "public_url_template", "label": "Public URL template", "type": "text", "required": False, "placeholder": "https://target.example/uploads/{filename}", "help": "Optional. Use {filename}; otherwise CyberScan tries to read a URL from the response."},
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _same_origin(left, right):
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (
        left_parsed.scheme.lower(),
        (left_parsed.hostname or "").lower(),
        left_parsed.port,
    ) == (
        right_parsed.scheme.lower(),
        (right_parsed.hostname or "").lower(),
        right_parsed.port,
    )


def _discover_url(response, filename):
    candidates = []
    try:
        payload = response.json()
        if isinstance(payload, dict):
            for key in ("url", "file_url", "location", "path"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    candidates.append(value)
    except (ValueError, json.JSONDecodeError):
        pass
    match = URL_RE.search(body_text(response))
    if match:
        candidates.append(match.group(0))
    for candidate in candidates:
        resolved = urljoin(response.url, candidate)
        if _same_origin(response.url, resolved) and filename in resolved:
            return resolved, False
    return "", bool(candidates)


def scan(url, upload_url="", file_field="", public_url_template=""):
    attempts = 0
    missing_inputs = []
    if not str(upload_url or "").strip():
        missing_inputs.append("upload_url")
    if not str(file_field or "").strip():
        missing_inputs.append("file_field")
    if missing_inputs:
        return inconclusive(
            "Upload URL and file field are required; no upload request was sent.",
            evidence={
                "missing_inputs": missing_inputs,
                "upload_attempted": False,
                "final_decision": "missing_required_inputs",
            },
            endpoint=url,
            parameter=file_field,
            requests_made=0,
        )
    target = str(upload_url).strip()
    file_field = str(file_field).strip()
    token = unique_token("upload")
    filename = f"{token}.html"
    content = f"<!doctype html><meta charset=utf-8><title>{token}</title><p>{token}</p>"
    marker_hash = f"sha256:{hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]}"
    try:
        attempts += 1
        response = safe_request(
            "POST",
            target,
            files={file_field: (filename, content.encode("utf-8"), "text/html")},
            allow_redirects=True,
        )
        discovered_url_rejected = False
        retrieval_source = "explicit_template" if public_url_template else "response_discovery"
        if public_url_template:
            public_url = public_url_template.replace("{filename}", filename)
        else:
            public_url, discovered_url_rejected = _discover_url(response, filename)
        evidence = {
            "upload_status": response.status_code,
            "file_field": file_field,
            "marker_hash": marker_hash,
            "retrieval_source": retrieval_source,
            "discovered_url_rejected": discovered_url_rejected,
        }
        if not 200 <= response.status_code < 300:
            evidence["final_decision"] = "upload_response_not_successful"
            return inconclusive(
                "The upload endpoint did not return a successful response, so storage could not be verified.",
                evidence=evidence,
                endpoint=target,
                parameter=file_field,
                requests_made=attempts,
            )
        if not public_url:
            evidence["final_decision"] = "no_safe_retrieval_url"
            return inconclusive(
                "The server accepted or processed the upload request, but no retrieval URL was available; acceptance alone is not proof of an unsafe upload.",
                evidence=evidence,
                endpoint=response.url,
                requests_made=attempts,
            )

        attempts += 1
        retrieved = safe_request("GET", public_url)
        body = body_text(retrieved)
        served_html = "text/html" in retrieved.headers.get("Content-Type", "").lower()
        served_as_attachment = "attachment" in retrieved.headers.get("Content-Disposition", "").lower()
        successful_retrieval = 200 <= retrieved.status_code < 300
        confirmed = successful_retrieval and token in body and served_html and not served_as_attachment
        evidence.update({
            "retrieval_status": retrieved.status_code,
            "retrieval_content_type": retrieved.headers.get("Content-Type", ""),
            "marker_retrieved": token in body,
            "served_as_attachment": served_as_attachment,
        })
        if confirmed:
            evidence["final_decision"] = "confirmed_active_marker_retrieval"
            return make_result(
                True,
                "A user-controlled HTML file was uploaded and served publicly as active HTML content.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Allowlist file types, verify content signatures, rename files, store outside the web root, and force safe download content types.",
                endpoint=retrieved.url,
                parameter=file_field,
                cwe="CWE-434",
                cvss=8.1,
                requests_made=attempts,
            )
        evidence["final_decision"] = "active_marker_retrieval_not_confirmed"
        return make_result(
            False,
            "The uploaded marker was not confirmed as publicly served active HTML content.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=public_url,
            parameter=file_field,
            cwe="CWE-434",
            requests_made=attempts,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(
            f"File-upload verification failed: {exc}",
            evidence={"final_decision": "transport_or_processing_error"},
            endpoint=target,
            parameter=file_field,
            requests_made=attempts,
        )
