from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter
from typing import Any

_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()
_MAX_FINDINGS = 100
_MAX_TEXT = 1200


def _clean(value: Any, limit: int = _MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return text[:limit]


def _severity(value: Any) -> str:
    normalized = _clean(value, 20).lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}.get(normalized, "Info")


def _fix_for(item: dict[str, Any]) -> str:
    supplied = _clean(item.get("recommendation"))
    if supplied:
        return supplied
    name = _clean(item.get("name") or item.get("scanner")).lower()
    defaults = {
        "sql": "Use parameterized queries, least-privilege database accounts, and server-side input validation.",
        "xss": "Apply context-aware output encoding, sanitize allowed HTML, and use a restrictive Content Security Policy.",
        "csrf": "Require a server-validated anti-CSRF token on every state-changing request and use SameSite cookies.",
        "idor": "Enforce object-level authorization on the server for every requested identifier.",
        "ssrf": "Allowlist outbound destinations and block private, link-local, and metadata networks after DNS resolution and redirects.",
        "cors": "Use an exact trusted-origin allowlist and enable credentialed CORS only where necessary.",
        "clickjacking": "Set CSP frame-ancestors and X-Frame-Options: DENY or SAMEORIGIN.",
        "upload": "Validate type and content, randomize stored names, store outside the web root, and serve as attachment.",
        "password": "Enforce strong passwords and MFA; verify only dedicated test accounts during assessments.",
        "rate": "Apply endpoint-specific throttling, lockout protections, and monitoring to sensitive operations.",
    }
    for key, recommendation in defaults.items():
        if key in name:
            return recommendation
    return "Manually verify the evidence, remediate the root cause, and add a regression test before closing the finding."


def _normalize_findings(scan_results: Any) -> list[dict[str, str]]:
    if not isinstance(scan_results, list):
        return []
    findings: list[dict[str, str]] = []
    for raw in scan_results[:_MAX_FINDINGS]:
        if not isinstance(raw, dict):
            continue
        status = _clean(raw.get("status"), 30).lower()
        vulnerable = raw.get("vulnerable") is True
        if not vulnerable and status not in {"confirmed", "potential", "error"}:
            continue
        name = _clean(raw.get("name") or raw.get("scanner") or "Finding", 100)
        confidence = _clean(raw.get("confidence") or "Low", 20)
        evidence = raw.get("evidence")
        if isinstance(evidence, (dict, list)):
            evidence_text = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        else:
            evidence_text = _clean(evidence)
        description = _clean(raw.get("result") or raw.get("description") or "No description supplied.")
        if evidence_text:
            description = f"{description} Evidence: {_clean(evidence_text, 500)}"
        findings.append(
            {
                "name": name,
                "severity": _severity(raw.get("severity")),
                "description": description,
                "fix": _fix_for(raw),
                "confidence": confidence,
                "status": status or ("confirmed" if vulnerable else "potential"),
            }
        )
    return findings


def analyze_scan(scan_results: Any) -> dict[str, Any]:
    """Create a deterministic, offline security summary.

    No target data is sent to a third party. The endpoint keeps its original name for
    UI compatibility, but the analysis is local and evidence-driven.
    """
    normalized = _normalize_findings(scan_results)
    payload = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
    cache_key = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached is not None:
            return cached

    counts = Counter(item["severity"] for item in normalized)
    confirmed = sum(item["status"] == "confirmed" for item in normalized)
    potential = sum(item["status"] == "potential" for item in normalized)
    errors = sum(item["status"] == "error" for item in normalized)
    if not normalized:
        summary = "No confirmed, potential, or scanner-error findings were supplied for analysis."
    else:
        summary = (
            f"Reviewed {len(normalized)} saved finding(s): {confirmed} confirmed, "
            f"{potential} potential, and {errors} scanner error(s). "
            f"Severity distribution: Critical {counts['Critical']}, High {counts['High']}, "
            f"Medium {counts['Medium']}, Low {counts['Low']}, Info {counts['Info']}. "
            "Prioritize high-confidence confirmed findings; manually validate potential findings before remediation."
        )

    result = {"summary": summary, "vulnerabilities": normalized, "analysis_mode": "local_deterministic"}
    with _CACHE_LOCK:
        if len(_CACHE) >= 128:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[cache_key] = result
    return result
