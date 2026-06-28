from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
import redis


class QueueConfigurationError(RuntimeError):
    """Raised when the optional Redis queue is enabled but misconfigured."""


class QueuePayloadError(RuntimeError):
    """Raised when an encrypted queue message cannot be decoded safely."""


@dataclass(slots=True)
class ReservedJob:
    payload: dict
    receipt: bytes
    worker_id: str


@dataclass(slots=True)
class DistributedQueue:
    client: Any
    cipher: Fernet
    queue_key: str = "cyberscan:scan_jobs:v1"
    cancel_prefix: str = "cyberscan:cancel:"
    processing_prefix: str = "cyberscan:processing:"
    heartbeat_prefix: str = "cyberscan:worker-heartbeat:"

    @classmethod
    def from_environment(cls, *, client=None) -> "DistributedQueue":
        redis_url = os.getenv("REDIS_URL", "").strip()
        encryption_key = os.getenv("QUEUE_ENCRYPTION_KEY", "").strip()
        if not redis_url and client is None:
            raise QueueConfigurationError("REDIS_URL is required when SCAN_QUEUE_BACKEND=redis.")
        if not encryption_key:
            raise QueueConfigurationError(
                "QUEUE_ENCRYPTION_KEY is required when SCAN_QUEUE_BACKEND=redis. "
                "Generate it with: python scripts/generate_secrets.py"
            )
        try:
            cipher = Fernet(encryption_key.encode("ascii"))
        except Exception as exc:
            raise QueueConfigurationError("QUEUE_ENCRYPTION_KEY is not a valid Fernet key.") from exc
        redis_client = client or redis.Redis.from_url(
            redis_url,
            decode_responses=False,
            socket_connect_timeout=float(os.getenv("REDIS_CONNECT_TIMEOUT", "3")),
            socket_timeout=float(os.getenv("REDIS_SOCKET_TIMEOUT", "5")),
            health_check_interval=30,
        )
        return cls(
            client=redis_client,
            cipher=cipher,
            queue_key=os.getenv("REDIS_SCAN_QUEUE_KEY", "cyberscan:scan_jobs:v1").strip() or "cyberscan:scan_jobs:v1",
            cancel_prefix=os.getenv("REDIS_CANCEL_PREFIX", "cyberscan:cancel:").strip() or "cyberscan:cancel:",
            processing_prefix=os.getenv("REDIS_PROCESSING_PREFIX", "cyberscan:processing:").strip() or "cyberscan:processing:",
            heartbeat_prefix=os.getenv("REDIS_HEARTBEAT_PREFIX", "cyberscan:worker-heartbeat:").strip() or "cyberscan:worker-heartbeat:",
        )

    def ping(self) -> bool:
        return bool(self.client.ping())

    def enqueue(self, payload: dict) -> int:
        if not isinstance(payload, dict):
            raise TypeError("Queue payload must be a JSON object.")
        token = self._encode(payload)
        return int(self.client.lpush(self.queue_key, token))

    def reserve(self, worker_id: str, timeout: int = 5) -> ReservedJob | None:
        worker_id = self._validate_worker_id(worker_id)
        timeout = max(0, int(timeout))
        token = self.client.brpoplpush(self.queue_key, self._processing_key(worker_id), timeout=timeout)
        if not token:
            return None
        return ReservedJob(payload=self._decode(token), receipt=bytes(token), worker_id=worker_id)

    def acknowledge(self, job: ReservedJob) -> None:
        self.client.lrem(self._processing_key(job.worker_id), 1, job.receipt)

    def requeue(self, job: ReservedJob) -> None:
        processing_key = self._processing_key(job.worker_id)
        with self.client.pipeline(transaction=True) as pipeline:
            pipeline.lrem(processing_key, 1, job.receipt)
            pipeline.rpush(self.queue_key, job.receipt)
            pipeline.execute()

    def dequeue(self, timeout: int = 5) -> dict | None:
        """Convenience API for tests/single-consumer tools; reserves and immediately acknowledges."""
        job = self.reserve("direct", timeout=timeout)
        if job is None:
            return None
        self.acknowledge(job)
        return job.payload

    def heartbeat(self, worker_id: str, *, ttl_seconds: int = 30) -> None:
        worker_id = self._validate_worker_id(worker_id)
        self.client.setex(self._heartbeat_key(worker_id), max(10, int(ttl_seconds)), b"1")

    def clear_heartbeat(self, worker_id: str) -> None:
        self.client.delete(self._heartbeat_key(self._validate_worker_id(worker_id)))

    def recover_abandoned(self) -> int:
        """Return jobs owned by workers whose heartbeat expired back to the main queue."""
        recovered = 0
        pattern = f"{self.processing_prefix}*"
        for raw_key in self.client.scan_iter(match=pattern):
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            worker_id = key[len(self.processing_prefix):]
            if not worker_id or self.client.exists(self._heartbeat_key(worker_id)):
                continue
            while True:
                token = self.client.rpop(key)
                if token is None:
                    break
                self.client.rpush(self.queue_key, token)
                recovered += 1
            self.client.delete(key)
        return recovered

    def request_cancel(self, scan_id: int, *, ttl_seconds: int = 86400) -> None:
        self.client.setex(self._cancel_key(scan_id), max(60, int(ttl_seconds)), b"1")

    def cancel_requested(self, scan_id: int) -> bool:
        return bool(self.client.exists(self._cancel_key(scan_id)))

    def clear_cancel(self, scan_id: int) -> None:
        self.client.delete(self._cancel_key(scan_id))

    def queue_depth(self) -> int:
        return int(self.client.llen(self.queue_key))

    def _encode(self, payload: dict) -> bytes:
        envelope = {"version": 1, "queued_at": int(time.time()), "payload": payload}
        raw = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self.cipher.encrypt(raw)

    def _decode(self, token: bytes) -> dict:
        try:
            raw = self.cipher.decrypt(token)
            envelope = json.loads(raw.decode("utf-8"))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QueuePayloadError("Unable to decrypt or decode a queued scan job.") from exc
        if not isinstance(envelope, dict) or envelope.get("version") != 1 or not isinstance(envelope.get("payload"), dict):
            raise QueuePayloadError("Unsupported or malformed scan job envelope.")
        return envelope["payload"]

    @staticmethod
    def _validate_worker_id(worker_id: str) -> str:
        value = str(worker_id or "").strip()
        if not value or len(value) > 120 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for ch in value):
            raise ValueError("Invalid queue worker identifier.")
        return value

    def _cancel_key(self, scan_id: int) -> str:
        return f"{self.cancel_prefix}{int(scan_id)}"

    def _processing_key(self, worker_id: str) -> str:
        return f"{self.processing_prefix}{worker_id}"

    def _heartbeat_key(self, worker_id: str) -> str:
        return f"{self.heartbeat_prefix}{worker_id}"


_QUEUE: DistributedQueue | None = None


def get_queue(*, refresh: bool = False, client=None) -> DistributedQueue:
    global _QUEUE
    if refresh or _QUEUE is None or client is not None:
        queue = DistributedQueue.from_environment(client=client)
        if client is None:
            _QUEUE = queue
        return queue
    return _QUEUE


def redis_backend_enabled() -> bool:
    return os.getenv("SCAN_QUEUE_BACKEND", "local").strip().lower() == "redis"
