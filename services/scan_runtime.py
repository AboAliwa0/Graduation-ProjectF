from __future__ import annotations

import contextlib
import contextvars
import threading
from dataclasses import dataclass, field
from typing import Callable, Iterator

import requests


class ScanCancelled(RuntimeError):
    """Raised when a user cancels an active scan."""


class RequestBudgetExceeded(RuntimeError):
    """Raised before a scan can exceed its configured HTTP request budget."""


@dataclass(slots=True)
class ScanRuntime:
    scan_id: int
    user_id: int
    request_budget: int = 120
    default_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    allow_private: bool = False
    cancel_event: threading.Event = field(default_factory=threading.Event)
    request_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)
    session: requests.Session = field(default_factory=requests.Session)
    ephemeral: dict = field(default_factory=dict)
    artifacts: dict = field(default_factory=dict)
    cancel_checker: Callable[[], bool] | None = None

    def __post_init__(self) -> None:
        # Do not inherit machine-level proxy credentials or ambient auth by default.
        self.session.trust_env = False
        if self.cookies:
            self.session.cookies.update(self.cookies)

    def is_cancelled(self) -> bool:
        if self.cancel_event.is_set():
            return True
        if self.cancel_checker is not None:
            try:
                return bool(self.cancel_checker())
            except Exception:
                # A temporary queue/Redis outage must not turn into a false cancellation.
                return False
        return False

    def before_request(self) -> int:
        if self.is_cancelled():
            raise ScanCancelled("Scan cancellation was requested.")
        with self.lock:
            if self.request_count >= self.request_budget:
                raise RequestBudgetExceeded(
                    f"The scan reached its HTTP request budget ({self.request_budget})."
                )
            self.request_count += 1
            return self.request_count

    def cancel(self) -> None:
        self.cancel_event.set()


_CURRENT_RUNTIME: contextvars.ContextVar[ScanRuntime | None] = contextvars.ContextVar(
    "cyberscan_runtime", default=None
)


@contextlib.contextmanager
def activate_runtime(runtime: ScanRuntime) -> Iterator[ScanRuntime]:
    token = _CURRENT_RUNTIME.set(runtime)
    try:
        yield runtime
    finally:
        _CURRENT_RUNTIME.reset(token)
        runtime.session.close()


def current_runtime() -> ScanRuntime | None:
    return _CURRENT_RUNTIME.get()
