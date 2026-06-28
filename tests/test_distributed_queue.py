from __future__ import annotations

from cryptography.fernet import Fernet
import fakeredis

from services.distributed_queue import DistributedQueue
from services.scan_runtime import ScanCancelled, ScanRuntime


def test_redis_queue_encrypts_sensitive_job(monkeypatch):
    secret = "Bearer sensitive-token-never-plaintext"
    client = fakeredis.FakeRedis(decode_responses=False)
    queue = DistributedQueue(client=client, cipher=Fernet(Fernet.generate_key()))
    queue.enqueue({"scan_id": 77, "runtime": {"default_headers": {"Authorization": secret}}})
    raw = client.lindex(queue.queue_key, 0)
    assert raw and secret.encode() not in raw
    decoded = queue.dequeue(timeout=1)
    assert decoded["runtime"]["default_headers"]["Authorization"] == secret


def test_distributed_cancel_is_cooperative():
    client = fakeredis.FakeRedis(decode_responses=False)
    queue = DistributedQueue(client=client, cipher=Fernet(Fernet.generate_key()))
    runtime = ScanRuntime(scan_id=88, user_id=1, cancel_checker=lambda: queue.cancel_requested(88))
    assert runtime.is_cancelled() is False
    queue.request_cancel(88)
    assert runtime.is_cancelled() is True
    try:
        runtime.before_request()
    except ScanCancelled:
        pass
    else:
        raise AssertionError("Distributed cancellation did not stop the request.")
    queue.clear_cancel(88)
    assert runtime.is_cancelled() is False


def test_redis_queue_is_fifo():
    client = fakeredis.FakeRedis(decode_responses=False)
    queue = DistributedQueue(client=client, cipher=Fernet(Fernet.generate_key()))
    queue.enqueue({"scan_id": 1})
    queue.enqueue({"scan_id": 2})
    assert queue.queue_depth() == 2
    assert queue.dequeue(timeout=1)["scan_id"] == 1
    assert queue.dequeue(timeout=1)["scan_id"] == 2


def test_abandoned_worker_job_is_recovered():
    client = fakeredis.FakeRedis(decode_responses=False)
    queue = DistributedQueue(client=client, cipher=Fernet(Fernet.generate_key()))
    queue.enqueue({"scan_id": 303})
    job = queue.reserve("dead-worker", timeout=1)
    assert job is not None
    assert queue.queue_depth() == 0
    assert queue.recover_abandoned() == 1
    assert queue.queue_depth() == 1
    assert queue.dequeue(timeout=1)["scan_id"] == 303
