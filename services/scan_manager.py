from __future__ import annotations

import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable

from services.scan_runtime import ScanRuntime

_MAX_WORKERS = max(1, min(int(os.getenv("SCAN_WORKERS", "4")), 16))
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="cyberscan")
_LOCK = threading.RLock()
_RUNTIMES: dict[int, ScanRuntime] = {}
_FUTURES: dict[int, Future] = {}


def register(runtime: ScanRuntime) -> None:
    with _LOCK:
        _RUNTIMES[runtime.scan_id] = runtime


def submit(scan_id: int, fn: Callable, *args, **kwargs) -> Future:
    future = _EXECUTOR.submit(fn, *args, **kwargs)
    with _LOCK:
        _FUTURES[scan_id] = future
    future.add_done_callback(lambda _: unregister(scan_id))
    return future


def cancel(scan_id: int) -> bool:
    with _LOCK:
        runtime = _RUNTIMES.get(scan_id)
        future = _FUTURES.get(scan_id)
        if runtime is None and future is None:
            return False
        if runtime is not None:
            runtime.cancel()
        # Future.cancel only succeeds for jobs that have not started. Active jobs
        # stop cooperatively before the next scanner/request.
        if future is not None:
            future.cancel()
        return True


def get_runtime(scan_id: int) -> ScanRuntime | None:
    with _LOCK:
        return _RUNTIMES.get(scan_id)


def unregister(scan_id: int) -> None:
    with _LOCK:
        _RUNTIMES.pop(scan_id, None)
        _FUTURES.pop(scan_id, None)


def active_count_for_user(user_id: int) -> int:
    with _LOCK:
        return sum(runtime.user_id == user_id for runtime in _RUNTIMES.values())
