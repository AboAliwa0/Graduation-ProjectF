from __future__ import annotations

from urllib.parse import urlparse

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


def scan(url, max_pages="8", navigation_timeout_ms="12000", allow_state_changing=False):
    runtime = current_runtime()
    ephemeral = runtime.ephemeral if runtime else {}
    try:
        inventory = crawl_spa(
            url,
            storage_state=ephemeral.get("browser_storage_state"),
            extra_headers=(runtime.default_headers if runtime else {}),
            max_pages=int(max_pages or 8),
            navigation_timeout_ms=int(navigation_timeout_ms or 12000),
            allow_state_changing=bool(allow_state_changing is True or str(allow_state_changing).lower() in {"1", "true", "yes", "on"}),
            allow_third_party=False,
        )
        payload = inventory.to_dict()
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
            )
        insecure_ws = [item for item in inventory.websocket_urls if item.startswith("ws://") and urlparse(url).scheme == "https"]
        evidence = {
            "pages_visited": inventory.pages_visited,
            "framework_hints": inventory.framework_hints,
            "request_count": len(inventory.requests),
            "xhr_fetch_count": sum(item.resource_type in {"xhr", "fetch"} for item in inventory.requests),
            "forms": inventory.forms[:50],
            "websocket_urls": inventory.websocket_urls,
            "blocked_request_count": len(inventory.blocked_requests),
            "console_errors": inventory.console_errors[:20],
            "warnings": inventory.warnings,
        }
        if insecure_ws:
            return make_result(
                True,
                "The HTTPS application initiated an unencrypted WebSocket connection.",
                severity="Medium",
                confidence="High",
                status="confirmed",
                evidence={**evidence, "insecure_websockets": insecure_ws},
                recommendation="Use wss:// for every WebSocket connection and enforce TLS at the gateway.",
                endpoint=url,
                cwe="CWE-319",
                cvss=5.3,
            )
        return make_result(
            False,
            f"Rendered {len(inventory.pages_visited)} page(s) with Chromium and discovered {len(inventory.requests)} network request(s).",
            severity="Info",
            confidence="High",
            evidence=evidence,
            recommendation="Review the exported modern-application inventory and run API/authorization checks against discovered endpoints.",
            endpoint=url,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except BrowserUnavailable as exc:
        return error_result(str(exc), endpoint=url)
    except Exception as exc:
        return error_result(f"Modern browser discovery failed: {exc}", endpoint=url)
