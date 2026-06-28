from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

import requests

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import body_text, make_result, normalized_text, safe_request, similarity, validate_target_url

meta = {
    "name": "Authorization Role Matrix",
    "severity": "High",
    "description": "Compares safe read-only responses across authorized test profiles to identify possible role or object authorization parity.",
    "category": "Access Control",
}
inputs = [
    {"name": "endpoints", "label": "Protected GET endpoints", "type": "textarea", "required": False, "placeholder": "/admin\n/api/account", "help": "One same-host endpoint per line. If empty, browser/OpenAPI discoveries are used."},
    {"name": "max_endpoints", "label": "Maximum endpoints", "type": "number", "required": False, "placeholder": "20", "help": "Read-only requests only."},
]

SENSITIVE_PATH = re.compile(r"/(admin|internal|management|private|accounts?|users?|billing|payments?)(?:[/_-]|$)", re.I)
RANK = {"anonymous": 0, "low": 1, "user": 1, "unknown": 1, "high": 2, "admin": 3}


def _candidate_endpoints(url: str, raw: str, runtime, limit: int) -> list[str]:
    candidates: list[str] = []
    if raw:
        pieces = re.split(r"[\r\n,]+", raw)
        candidates.extend(urljoin(url, item.strip()) for item in pieces if item.strip())
    if runtime:
        browser = runtime.artifacts.get("browser") or {}
        for item in browser.get("requests") or []:
            if isinstance(item, dict) and str(item.get("method")).upper() == "GET" and item.get("resource_type") in {"document", "xhr", "fetch"}:
                candidates.append(str(item.get("url") or ""))
        openapi = runtime.artifacts.get("openapi") or {}
        base = next(iter(openapi.get("server_urls") or [url]), url)
        for operation in openapi.get("operations") or []:
            if isinstance(operation, dict) and str(operation.get("method")).upper() == "GET" and "{" not in str(operation.get("path") or ""):
                candidates.append(urljoin(base.rstrip("/") + "/", str(operation.get("path") or "").lstrip("/")))
    target_host = (urlparse(url).hostname or "").lower()
    result: list[str] = []
    for candidate in candidates:
        try:
            candidate = validate_target_url(candidate)
        except Exception:
            continue
        if (urlparse(candidate).hostname or "").lower() != target_host:
            continue
        if candidate not in result:
            result.append(candidate)
        if len(result) >= limit:
            break
    return result


def _request_as(endpoint: str, profile: dict) -> dict:
    session = requests.Session()
    session.trust_env = False
    session.cookies.update(profile.get("cookies") or {})
    try:
        response = safe_request("GET", endpoint, session=session, headers=profile.get("headers") or {}, allow_redirects=False)
        text = normalized_text(body_text(response))[:200_000]
        return {
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type", "")[:200],
            "text": text,
            "length": len(text),
        }
    finally:
        session.close()


def scan(url, endpoints="", max_endpoints="20"):
    runtime = current_runtime()
    profiles = list((runtime.ephemeral if runtime else {}).get("auth_profiles") or [])
    if len(profiles) < 2:
        return make_result(False, "At least two authorized auth profiles are required for role comparison.", severity="Info", confidence="High", status="inconclusive", endpoint=url)
    profiles.sort(key=lambda item: RANK.get(str(item.get("expected_access") or "unknown"), 1))
    low = profiles[0]
    high = profiles[-1]
    limit = max(1, min(int(max_endpoints or 20), 60))
    candidates = _candidate_endpoints(url, str(endpoints or ""), runtime, limit)
    if not candidates:
        return make_result(False, "No safe same-host GET endpoints were supplied or discovered for role comparison.", severity="Info", confidence="High", status="inconclusive", endpoint=url)
    observations = []
    suspicious = []
    try:
        for endpoint in candidates:
            low_response = _request_as(endpoint, low)
            high_response = _request_as(endpoint, high)
            score = similarity(low_response["text"], high_response["text"])
            item = {
                "endpoint": endpoint,
                "low_profile": low.get("name", "low"),
                "high_profile": high.get("name", "high"),
                "low_status": low_response["status"],
                "high_status": high_response["status"],
                "similarity": round(score, 3),
                "sensitive_path": bool(SENSITIVE_PATH.search(urlparse(endpoint).path)),
            }
            observations.append(item)
            if item["sensitive_path"] and 200 <= low_response["status"] < 300 and 200 <= high_response["status"] < 300 and score >= 0.9 and low_response["length"] > 20:
                suspicious.append(item)
        if runtime is not None:
            runtime.artifacts["authorization_matrix"] = {
                "profiles": [{"name": p.get("name"), "expected_access": p.get("expected_access")} for p in profiles],
                "observations": observations,
            }
        if suspicious:
            return make_result(
                True,
                "A lower-privilege test profile received a highly similar successful response to a higher-privilege profile on sensitive-looking endpoint(s). This is a potential authorization issue requiring manual object-level validation.",
                severity="High",
                confidence="Medium",
                status="potential",
                evidence={"suspicious": suspicious, "observations": observations},
                recommendation="Verify the affected objects and functions with distinct test identities. Enforce authorization on every request using server-side subject, action, and object checks.",
                endpoint=suspicious[0]["endpoint"],
                cwe="CWE-862",
                cvss=7.5,
            )
        return make_result(False, "No high-similarity authorization parity was observed across the supplied read-only endpoints.", severity="Info", confidence="Medium", evidence={"observations": observations}, endpoint=url)
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return make_result(False, f"Authorization matrix assessment failed: {exc}", severity="Info", confidence="Low", status="error", endpoint=url)
