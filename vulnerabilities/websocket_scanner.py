from __future__ import annotations

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from services.websocket_support import WebSocketAssessmentError, inspect_websocket
from vulnerabilities.common import error_result, make_result

meta = {
    "name": "WebSocket Handshake Assessment",
    "severity": "Low",
    "description": "Performs a safe WebSocket handshake without fuzzing or sending application messages.",
    "category": "Modern Applications",
}
inputs = [
    {"name": "endpoint", "label": "WebSocket endpoint", "type": "url", "required": False, "placeholder": "wss://target.example/ws", "help": "Leave empty to use a WebSocket discovered by the browser scanner."},
    {"name": "origin", "label": "Origin header", "type": "text", "required": False, "placeholder": "https://target.example", "help": "Used only for the handshake."},
]


def scan(url, endpoint="", origin=""):
    runtime = current_runtime()
    if not endpoint and runtime:
        endpoint = next(iter((runtime.artifacts.get("browser") or {}).get("websocket_urls") or []), "")
    if not endpoint:
        return make_result(False, "No WebSocket endpoint was supplied or discovered.", severity="Info", confidence="High", status="inconclusive", endpoint=url)
    try:
        inventory = inspect_websocket(
            endpoint,
            target_url=url,
            headers=(runtime.default_headers if runtime else {}),
            cookies=(runtime.cookies if runtime else {}),
            origin=origin or None,
        )
        if runtime is not None:
            runtime.artifacts.setdefault("websockets", []).append(inventory.to_dict())
        if inventory.connected:
            return make_result(
                False,
                "WebSocket handshake succeeded. No messages were sent and no vulnerability is inferred from connectivity alone.",
                severity="Info",
                confidence="High",
                evidence=inventory.to_dict(),
                recommendation="Review origin validation, authentication, authorization, message schemas, size limits, and rate limits manually or with an approved protocol-specific test plan.",
                endpoint=endpoint,
            )
        return make_result(False, "WebSocket handshake did not succeed.", severity="Info", confidence="High", status="inconclusive", evidence=inventory.to_dict(), endpoint=endpoint)
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except WebSocketAssessmentError as exc:
        return make_result(False, str(exc), severity="Info", confidence="High", status="inconclusive", endpoint=endpoint)
    except Exception as exc:
        return error_result(f"WebSocket assessment failed: {exc}", endpoint=endpoint)
