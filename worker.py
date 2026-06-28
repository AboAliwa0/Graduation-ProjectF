from __future__ import annotations

import os
import signal
import socket
import sys
import threading
import time
import uuid

from app import run_scan
from database import connect, init_db, utc_now
from services.distributed_queue import QueueConfigurationError, QueuePayloadError, ReservedJob, get_queue
from services.scan_runtime import ScanRuntime

_STOP = threading.Event()


def _stop_worker(_signum, _frame):
    _STOP.set()


def _scan_was_cancelled(scan_id: int) -> bool:
    conn = connect()
    row = conn.execute("SELECT cancel_requested,status FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return bool(row and (row["cancel_requested"] or row["status"] == "cancelled"))


def _mark_cancelled(scan_id: int) -> None:
    conn = connect()
    conn.execute(
        "UPDATE scans SET status='cancelled',progress=0,error_message='Cancellation was requested before execution.',completed_at=? WHERE id=?",
        (utc_now(), scan_id),
    )
    conn.commit()
    conn.close()


def process_job(job: dict) -> None:
    scan_id = int(job["scan_id"])
    user_id = int(job["user_id"])
    queue = get_queue()
    if queue.cancel_requested(scan_id) or _scan_was_cancelled(scan_id):
        _mark_cancelled(scan_id)
        queue.clear_cancel(scan_id)
        return

    runtime_data = dict(job.get("runtime") or {})
    runtime = ScanRuntime(
        scan_id=scan_id,
        user_id=user_id,
        request_budget=int(runtime_data.get("request_budget", 120)),
        default_headers=dict(runtime_data.get("default_headers") or {}),
        cookies=dict(runtime_data.get("cookies") or {}),
        verify_tls=runtime_data.get("verify_tls", True) is not False,
        allow_private=bool(runtime_data.get("allow_private", False)),
        ephemeral=dict(runtime_data.get("ephemeral") or {}),
        cancel_checker=lambda: queue.cancel_requested(scan_id) or _scan_was_cancelled(scan_id),
    )
    try:
        run_scan(
            scan_id,
            user_id,
            str(job["url"]),
            list(job.get("selected") or []),
            dict(job.get("payload_data") or {}),
            runtime,
        )
    finally:
        queue.clear_cancel(scan_id)


def _heartbeat_loop(queue, worker_id: str, ttl: int) -> None:
    interval = max(3, ttl // 3)
    while not _STOP.wait(interval):
        try:
            queue.heartbeat(worker_id, ttl_seconds=ttl)
        except Exception as exc:
            print(f"Worker heartbeat warning: {exc}", file=sys.stderr, flush=True)


def main() -> int:
    signal.signal(signal.SIGTERM, _stop_worker)
    signal.signal(signal.SIGINT, _stop_worker)
    init_db()
    try:
        queue = get_queue()
        queue.ping()
    except QueueConfigurationError as exc:
        print(f"CyberScan worker configuration error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"CyberScan worker could not connect to Redis: {exc}", file=sys.stderr)
        return 3

    worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    heartbeat_ttl = max(15, int(os.getenv("WORKER_HEARTBEAT_TTL", "30")))
    queue.heartbeat(worker_id, ttl_seconds=heartbeat_ttl)
    recovered = queue.recover_abandoned()
    if recovered:
        print(f"Recovered {recovered} abandoned scan job(s).", flush=True)
    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop, args=(queue, worker_id, heartbeat_ttl), daemon=True
    )
    heartbeat_thread.start()

    print(f"CyberScan Redis worker started: {worker_id}", flush=True)
    try:
        while not _STOP.is_set():
            reserved: ReservedJob | None = None
            try:
                reserved = queue.reserve(worker_id, timeout=int(os.getenv("WORKER_POLL_SECONDS", "5")))
                if reserved is None:
                    queue.recover_abandoned()
                    continue
                process_job(reserved.payload)
                queue.acknowledge(reserved)
            except QueuePayloadError as exc:
                print(f"Rejected malformed queue message: {exc}", file=sys.stderr, flush=True)
                if reserved is not None:
                    queue.acknowledge(reserved)
            except Exception as exc:
                print(f"Worker job error: {exc}", file=sys.stderr, flush=True)
                if reserved is not None:
                    queue.requeue(reserved)
                time.sleep(1)
    finally:
        queue.clear_heartbeat(worker_id)
        _STOP.set()
        heartbeat_thread.join(timeout=2)
    print("CyberScan Redis worker stopped.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
