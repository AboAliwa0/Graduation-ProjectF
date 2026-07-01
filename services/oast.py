from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any
from urllib.parse import urlparse

from vulnerabilities.common import UnsafeTargetError, env_bool, validate_target_url

_lock = threading.Lock()
_events: dict[str, threading.Event] = {}
_hits: dict[str, list[dict[str, Any]]] = {}


class OASTConfigurationError(ValueError):
    pass


def validate_callback_base_url(value: str) -> str:
    base = str(value or "").strip().rstrip("/")
    if not base:
        raise OASTConfigurationError("A callback base URL is required.")
    parsed = urlparse(base)
    if parsed.query or parsed.fragment:
        raise OASTConfigurationError("Callback base URLs cannot contain a query string or fragment.")
    try:
        validate_target_url(
            base,
            allow_private=env_bool("OAST_ALLOW_PRIVATE_CALLBACKS", False),
        )
    except UnsafeTargetError as exc:
        raise OASTConfigurationError(str(exc)) from exc
    return base


def token_fingerprint(token: str) -> str:
    return f"sha256:{hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]}"


def register(token: str) -> None:
    with _lock:
        _events[token] = threading.Event()
        _hits[token] = []


def is_registered(token: str) -> bool:
    with _lock:
        return token in _events


def record_hit(token: str, details: dict[str, Any] | None = None) -> bool:
    with _lock:
        event = _events.get(token)
        if event is None:
            return False
        event_name = str((details or {}).get("event", "callback"))
        if event_name not in {"callback", "script_fetch", "execution_beacon"}:
            event_name = "callback"
        _hits.setdefault(token, []).append({"time": time.time(), "event": event_name})
        event.set()
        return True


def wait_for_hit(token: str, timeout: float = 3.0) -> list[dict[str, Any]]:
    with _lock:
        event = _events.get(token)
    if event is None:
        return []
    event.wait(timeout)
    with _lock:
        return list(_hits.get(token, []))


def cleanup(token: str) -> None:
    with _lock:
        _events.pop(token, None)
        _hits.pop(token, None)
