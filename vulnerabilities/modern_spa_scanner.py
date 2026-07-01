from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse
from urllib.parse import parse_qsl, urlencode, urlunparse

from services.browser_crawler import BrowserUnavailable, crawl_spa
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import error_result, make_result

meta = {
    "name": "Modern SPA Browser Discovery",
    "severity": "Low",
    "description": "Uses a real Chromium browser to render JavaScript applications and inventory routes, forms, fetch/XHR calls, and WebSockets.",
    "category": "Modern Applications",
}
inputs = [
    {"name": "max_pages", "label": "Maximum rendered pages", "type": "number", "required": False, "placeholder": "8", "help": "Same-origin GET navigation only; maximum 30."},
    {"name": "navigation_timeout_ms", "label": "Navigation timeout (ms)", "type": "number", "required": False, "placeholder": "12000", "help": "Maximum 60000 ms per page."},
    {"name": "allow_state_changing", "label": "Allow browser POST/PUT/PATCH/DELETE", "type": "boolean", "required": False, "help": "Keep disabled unless the isolated test account and target are prepared for state changes."},
]

SENSITIVE_KEY_RE = re.compile(r"(authorization|cookie|token|secret|password|api[-_]?key|session|storage)", re.I)
TOKEN_VALUE_RE = re.compile(r"(bearer\s+\S+|eyJ[a-zA-Z0-9_-]{10,}\.|(?:sk|ghp|glpat|xox[baprs])[-_][a-zA-Z0-9_-]{8,})", re.I)
SENSITIVE_QUERY_RE = re.compile(
    r"(?i)([?&](?:authorization|api[-_]?key|access[-_]?token|token|secret|password|session)=)[^&#\s]+"
)


def _parse_bounded_int(value, *, default: int, minimum: int, maximum: int, label: str) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a valid integer.") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}.")
    return parsed


def _redact_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        query = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            if SENSITIVE_KEY_RE.search(key) or TOKEN_VALUE_RE.search(item):
                item = "<redacted>"
            query.append((key, item))
        fragment = "<redacted>" if parsed.fragment and TOKEN_VALUE_RE.search(parsed.fragment) else parsed.fragment
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True), fragment=fragment))
    except Exception:
        return SENSITIVE_QUERY_RE.sub(r"\1<redacted>", TOKEN_VALUE_RE.sub("<redacted>", value))


def _sanitize_browser_payload(value: Any, *, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(item_key): _sanitize_browser_payload(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_browser_payload(item, key=key) for item in value[:2000]]
    if isinstance(value, str):
        if "url" in key.lower() or key.lower() in {"action", "page", "endpoint"}:
            return _redact_url(value)
        return SENSITIVE_QUERY_RE.sub(r"\1<redacted>", TOKEN_VALUE_RE.sub("<redacted>", value))
    return value


def scan(url, max_pages="8", navigation_timeout_ms="12000", allow_state_changing=False):
    runtime = current_runtime()
    started = runtime.request_count if runtime is not None else 0
    ephemeral = runtime.ephemeral if runtime else {}
    try:
        parsed_max_pages = _parse_bounded_int(max_pages, default=8, minimum=1, maximum=30, label="max_pages")
        parsed_timeout = _parse_bounded_int(
            navigation_timeout_ms,
            default=12000,
            minimum=2000,
            maximum=60000,
            label="navigation_timeout_ms",
        )
    except ValueError as exc:
        return make_result(
            False,
            str(exc),
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={
                "max_pages": str(max_pages),
                "navigation_timeout_ms": str(navigation_timeout_ms),
                "browser_status": "not_started",
            },
            endpoint=url,
            requests_made=0,
        )
    try:
        inventory = crawl_spa(
            url,
            storage_state=ephemeral.get("browser_storage_state"),
            extra_headers=(runtime.default_headers if runtime else {}),
            max_pages=parsed_max_pages,
            navigation_timeout_ms=parsed_timeout,
            allow_state_changing=bool(allow_state_changing is True or str(allow_state_changing).lower() in {"1", "true", "yes", "on"}),
            allow_third_party=False,
        )
        payload = _sanitize_browser_payload(inventory.to_dict())
        requests_made = max(0, runtime.request_count - started) if runtime is not None else sum(
            not item.blocked for item in inventory.requests
        )
        if runtime is not None:
            runtime.artifacts["browser"] = payload
        if not inventory.pages_visited:
            return make_result(
                False,
                "Chromium could not render the authorized target.",
                severity="Info",
                confidence="High",
                status="inconclusive",
                evidence={"warnings": inventory.warnings, "blocked_requests": inventory.blocked_requests[:20]},
                recommendation="Install the Playwright-managed Chromium build and check local browser enterprise policies, DNS, TLS, and target scope settings.",
                endpoint=url,
                requests_made=requests_made,
            )
        insecure_ws = [item for item in inventory.websocket_urls if item.startswith("ws://") and urlparse(url).scheme == "https"]
        safe_insecure_ws = [_redact_url(item) for item in insecure_ws]
        evidence = {
            "pages_visited": payload.get("pages_visited", []),
            "framework_hints": inventory.framework_hints,
            "request_count": len(inventory.requests),
            "xhr_fetch_count": sum(item.resource_type in {"xhr", "fetch"} for item in inventory.requests),
            "forms": payload.get("forms", [])[:50],
            "websocket_urls": payload.get("websocket_urls", []),
            "blocked_request_count": len(inventory.blocked_requests),
            "console_errors": payload.get("console_errors", [])[:20],
            "warnings": payload.get("warnings", []),
        }
        if insecure_ws:
            return make_result(
                True,
                "The HTTPS application initiated an unencrypted WebSocket connection.",
                severity="Medium",
                confidence="High",
                status="confirmed",
                evidence={**evidence, "insecure_websockets": safe_insecure_ws},
                recommendation="Use wss:// for every WebSocket connection and enforce TLS at the gateway.",
                endpoint=url,
                cwe="CWE-319",
                cvss=5.3,
                requests_made=requests_made,
            )
        return make_result(
            False,
            f"Rendered {len(inventory.pages_visited)} page(s) with Chromium and discovered {len(inventory.requests)} network request(s).",
            severity="Info",
            confidence="High",
            evidence=evidence,
            recommendation="Review the exported modern-application inventory and run API/authorization checks against discovered endpoints.",
            endpoint=url,
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except BrowserUnavailable as exc:
        return make_result(
            False,
            str(exc),
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"browser_available": False, "browser_status": "dependency_unavailable"},
            endpoint=url,
            requests_made=max(0, runtime.request_count - started) if runtime is not None else 0,
        )
    except Exception as exc:
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 0
        return error_result(f"Modern browser discovery failed: {exc}", endpoint=url, requests_made=requests_made)
