from __future__ import annotations

import ssl
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urlparse, urlunparse

from services.scan_runtime import current_runtime
from vulnerabilities.common import validate_target_url


class WebSocketAssessmentError(RuntimeError):
    pass


@dataclass(slots=True)
class WebSocketInventory:
    url: str
    connected: bool
    subprotocol: str = ""
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _policy_url(ws_url: str) -> str:
    parsed = urlparse(ws_url)
    if parsed.scheme not in {"ws", "wss"}:
        raise WebSocketAssessmentError("WebSocket URL must use ws:// or wss://.")
    mapped = parsed._replace(scheme="https" if parsed.scheme == "wss" else "http")
    return urlunparse(mapped)


def inspect_websocket(
    ws_url: str,
    *,
    target_url: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    origin: str | None = None,
    subprotocols: list[str] | None = None,
    timeout: float = 6.0,
) -> WebSocketInventory:
    try:
        import websocket
    except Exception as exc:  # pragma: no cover
        raise WebSocketAssessmentError("websocket-client is not installed.") from exc

    policy = validate_target_url(_policy_url(ws_url))
    target = validate_target_url(target_url)
    if (urlparse(policy).hostname or "").lower() != (urlparse(target).hostname or "").lower():
        raise WebSocketAssessmentError("WebSocket endpoint must use the authorized target hostname.")

    runtime = current_runtime()
    if runtime is not None:
        runtime.before_request()

    header_list = []
    merged_headers = dict(headers or {})
    for key in list(merged_headers):
        if key.lower() in {"host", "content-length", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version"}:
            merged_headers.pop(key, None)
    for key, value in merged_headers.items():
        header_list.append(f"{key}: {value}")
    cookie = "; ".join(f"{key}={value}" for key, value in (cookies or {}).items()) or None
    sslopt = {"cert_reqs": ssl.CERT_REQUIRED}
    if runtime is not None and not runtime.verify_tls:
        sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}

    connection = None
    try:
        connection = websocket.create_connection(
            ws_url,
            timeout=max(1.0, min(float(timeout), 30.0)),
            header=header_list,
            cookie=cookie,
            origin=origin,
            subprotocols=subprotocols or None,
            sslopt=sslopt,
            enable_multithread=True,
        )
        response_headers = {}
        raw_headers = getattr(connection, "headers", None)
        if isinstance(raw_headers, dict):
            response_headers = {str(k): str(v)[:500] for k, v in raw_headers.items()}
        return WebSocketInventory(
            url=ws_url,
            connected=True,
            subprotocol=str(getattr(connection, "subprotocol", "") or ""),
            response_status=int(getattr(connection, "status", 101) or 101),
            response_headers=response_headers,
        )
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        return WebSocketInventory(url=ws_url, connected=False, response_status=status, error=str(exc)[:1000])
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
