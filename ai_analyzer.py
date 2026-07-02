from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter
from typing import Any
from urllib.parse import urlparse, urlunparse

from vulnerabilities.common import sanitize_url

_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()
_MAX_FINDINGS = 100
_MAX_TEXT = 1200
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|"
    r"access_token|refresh_token|id_token|api_key|token|session|sid)\b\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
)
_SENSITIVE_KEYS = {
    "authorization", "proxy_authorization", "cookie", "cookies", "set_cookie",
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "id_token", "api_key", "apikey", "session", "sid", "callback_url",
    "callback_base_url", "oast_token", "oast_url",
}
_LIMITATIONS = [
    "Scanner errors and inconclusive checks are operational limitations, not security vulnerabilities.",
    "Automated scanning does not prove complete security or that all vulnerabilities were found.",
    "Risk Score is an aggregate project score and is not CVSS.",
]


def _clean(value: Any, limit: int = _MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return text[:limit]


def _sanitize_ai_url(value: str) -> str:
    cleaned = sanitize_url(value)
    try:
        parsed = urlparse(cleaned)
        parts = parsed.path.split("/")
        if "oast" in [part.lower() for part in parts]:
            index = next(index for index, part in enumerate(parts) if part.lower() == "oast")
            parts[index + 1 :] = ["redacted"] if len(parts) > index + 1 else []
            cleaned = urlunparse(parsed._replace(path="/".join(parts), query="", fragment=""))
    except Exception:
        pass
    return cleaned


def _safe_text(value: Any, limit: int = _MAX_TEXT) -> str:
    text = _clean(value, limit * 2)
    text = _URL_RE.sub(lambda match: _sanitize_ai_url(match.group(0)), text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
    return text[:limit]


def _sensitive_key(value: Any) -> bool:
    key = str(value or "").strip().lower().replace("-", "_")
    return key in _SENSITIVE_KEYS or key.endswith(("_password", "_secret", "_token", "_cookie"))


def _redact_evidence(value: Any, *, key: str = "") -> Any:
    if _sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact_evidence(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_evidence(item, key=key) for item in value]
    if isinstance(value, str):
        return _safe_text(value, 500)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(value, 200)


def _severity(value: Any) -> str:
    normalized = _clean(value, 20).lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}.get(normalized, "Info")


def _fix_for(item: dict[str, Any]) -> str:
    supplied = _safe_text(item.get("recommendation"))
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


def _normalized_item(raw: dict[str, Any], status: str) -> dict[str, str]:
    name = _safe_text(raw.get("name") or raw.get("scanner") or "Scanner result", 100)
    confidence = _safe_text(raw.get("confidence") or "Low", 20)
    description = _safe_text(raw.get("result") or raw.get("description") or "No description supplied.")
    evidence = raw.get("evidence")
    if evidence not in (None, "", {}, []):
        safe_evidence = _redact_evidence(evidence)
        evidence_text = json.dumps(safe_evidence, ensure_ascii=False, sort_keys=True, default=str)
        description = _safe_text(f"{description} Evidence summary: {evidence_text}")
    return {
        "name": name,
        "severity": _severity(raw.get("severity")),
        "description": description,
        "fix": _fix_for(raw),
        "confidence": confidence,
        "status": status,
    }


def _normalize_results(scan_results: Any) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if not isinstance(scan_results, list):
        return [], []
    findings: list[dict[str, str]] = []
    operational: list[dict[str, str]] = []
    for raw in scan_results[:_MAX_FINDINGS]:
        if not isinstance(raw, dict):
            continue
        status = _clean(raw.get("status"), 30).lower()
        vulnerable = raw.get("vulnerable") is True
        if not status and vulnerable:
            status = "confirmed"
        if status in {"confirmed", "potential"}:
            findings.append(_normalized_item(raw, status))
            continue
        if status in {"error", "inconclusive"}:
            operational.append(_normalized_item(raw, status))
        elif status and status != "not_vulnerable":
            operational.append(_normalized_item(raw, "unknown"))
    return findings, operational


def _normalize_findings(scan_results: Any) -> list[dict[str, str]]:
    return _normalize_results(scan_results)[0]


def analyze_scan(scan_results: Any) -> dict[str, Any]:
    """Create a deterministic, offline security summary.

    No target data is sent to a third party. The endpoint keeps its original name for
    UI compatibility, but the analysis is local and evidence-driven.
    """
    normalized, operational = _normalize_results(scan_results)
    payload = json.dumps({"findings": normalized, "operational": operational}, ensure_ascii=False, sort_keys=True)
    cache_key = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached is not None:
            return cached

    counts = Counter(item["severity"] for item in normalized)
    confirmed = sum(item["status"] == "confirmed" for item in normalized)
    potential = sum(item["status"] == "potential" for item in normalized)
    errors = sum(item["status"] == "error" for item in operational)
    inconclusive = sum(item["status"] == "inconclusive" for item in operational)
    summary = (
        f"Reviewed {len(normalized)} security finding(s): {confirmed} confirmed and {potential} potential. "
        f"Severity distribution: Critical {counts['Critical']}, High {counts['High']}, "
        f"Medium {counts['Medium']}, Low {counts['Low']}, Info {counts['Info']}. "
        f"Scanner errors ({errors}) and inconclusive checks ({inconclusive}) are operational limitations "
        "and are not counted as vulnerabilities. Automated scanning does not prove complete security. "
        "Risk Score is an aggregate project score and is not CVSS."
    )

    result = {
        "summary": summary,
        "vulnerabilities": normalized,
        "operational_results": operational,
        "finding_count": len(normalized),
        "operational_count": len(operational),
        "recommendations": list(dict.fromkeys(item["fix"] for item in normalized)),
        "limitations": list(_LIMITATIONS),
        "analysis_mode": "local_deterministic",
    }
    with _CACHE_LOCK:
        if len(_CACHE) >= 128:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[cache_key] = result
    return result
