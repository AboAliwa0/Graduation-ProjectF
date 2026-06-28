from __future__ import annotations

import threading
import time
from typing import Any

_lock = threading.Lock()
_events: dict[str, threading.Event] = {}
_hits: dict[str, list[dict[str, Any]]] = {}


def register(token: str) -> None:
    with _lock:
        _events[token] = threading.Event()
        _hits[token] = []


def record_hit(token: str, details: dict[str, Any] | None = None) -> bool:
    with _lock:
        event = _events.get(token)
        if event is None:
            return False
        _hits.setdefault(token, []).append({"time": time.time(), **(details or {})})
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
