from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import json
import re
from urllib.parse import urljoin

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


def _discover_url(response, filename):
    try:
        payload = response.json()
        if isinstance(payload, dict):
            for key in ("url", "file_url", "location", "path"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return urljoin(response.url, value)
    except (ValueError, json.JSONDecodeError):
        pass
    match = URL_RE.search(body_text(response))
    if match:
        return match.group(0)
    return ""


def scan(url, upload_url="", file_field="", public_url_template=""):
    missing_inputs = []
    if not str(upload_url or "").strip():
        missing_inputs.append("upload_url")
    if not str(file_field or "").strip():
        missing_inputs.append("file_field")
    if missing_inputs:
        return inconclusive(
            "Upload URL and file field are required; no upload request was sent.",
            evidence={"missing_inputs": missing_inputs, "upload_attempted": False},
            endpoint=url,
            parameter=file_field,
            requests_made=0,
        )
    target = str(upload_url).strip()
    file_field = str(file_field).strip()
    token = unique_token("upload")
    filename = f"{token}.html"
    content = f"<!doctype html><meta charset=utf-8><title>{token}</title><p>{token}</p>"
    try:
        response = safe_request(
            "POST",
            target,
            files={file_field: (filename, content.encode("utf-8"), "text/html")},
            allow_redirects=True,
        )
        public_url = public_url_template.replace("{filename}", filename) if public_url_template else _discover_url(response, filename)
        evidence = {
            "upload_status": response.status_code,
            "filename": filename,
            "file_field": file_field,
            "public_url": public_url,
        }
        if not public_url:
            return inconclusive(
                "The server accepted or processed the upload request, but no retrieval URL was available; acceptance alone is not proof of an unsafe upload.",
                evidence=evidence,
                endpoint=response.url,
                requests_made=1,
            )

        retrieved = safe_request("GET", public_url)
        body = body_text(retrieved)
        served_html = "text/html" in retrieved.headers.get("Content-Type", "").lower()
        confirmed = retrieved.status_code == 200 and token in body and served_html
        evidence.update({
            "retrieval_status": retrieved.status_code,
            "retrieval_content_type": retrieved.headers.get("Content-Type", ""),
            "marker_retrieved": token in body,
        })
        if confirmed:
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
                requests_made=2,
            )
        return make_result(
            False,
            "The uploaded marker was not confirmed as publicly served active HTML content.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=public_url,
            parameter=file_field,
            cwe="CWE-434",
            requests_made=2,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"File-upload verification failed: {exc}", endpoint=target, parameter=file_field)
