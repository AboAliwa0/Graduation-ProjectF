from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any
from urllib.parse import urlparse

from services.scan_runtime import current_runtime
from vulnerabilities.common import validate_target_url


class GrpcAssessmentError(RuntimeError):
    pass


@dataclass(slots=True)
class GrpcInventory:
    target: str
    tls: bool
    reflection_available: bool
    services: list[str] = field(default_factory=list)
    descriptor_files: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate_target(target: str, tls: bool) -> str:
    value = str(target or "").strip()
    if ":" not in value:
        raise GrpcAssessmentError("gRPC target must be host:port.")
    host, _, raw_port = value.rpartition(":")
    host = host.strip("[]")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise GrpcAssessmentError("gRPC target port is invalid.") from exc
    if not host or not (1 <= port <= 65535):
        raise GrpcAssessmentError("gRPC target is invalid.")
    validate_target_url(f"{'https' if tls else 'http'}://{host}:{port}")
    return value


def inspect_grpc_reflection(
    target: str,
    *,
    tls: bool = True,
    metadata: dict[str, str] | None = None,
    timeout: float = 8.0,
) -> GrpcInventory:
    target = _validate_target(target, tls)
    try:
        import grpc
        from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
        from google.protobuf import descriptor_pb2
    except Exception as exc:  # pragma: no cover
        raise GrpcAssessmentError("Install grpcio, grpcio-reflection, and protobuf to inspect gRPC reflection.") from exc

    runtime = current_runtime()
    if runtime is not None:
        runtime.before_request()
    call_metadata = tuple((str(k), str(v)) for k, v in (metadata or {}).items() if str(k).lower() not in {"host", "content-length"})
    if tls:
        channel = grpc.secure_channel(target, grpc.ssl_channel_credentials())
    else:
        channel = grpc.insecure_channel(target)
    inventory = GrpcInventory(target=target, tls=tls, reflection_available=False)
    try:
        grpc.channel_ready_future(channel).result(timeout=max(1.0, min(float(timeout), 30.0)))
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(list_services="")
        responses = stub.ServerReflectionInfo(iter([request]), timeout=timeout, metadata=call_metadata)
        services: list[str] = []
        for response in responses:
            if response.HasField("list_services_response"):
                services.extend(service.name for service in response.list_services_response.service)
        inventory.reflection_available = True
        inventory.services = sorted(set(services))[:500]

        files: set[str] = set()
        for service in inventory.services[:100]:
            if service.startswith("grpc.reflection."):
                continue
            if runtime is not None:
                runtime.before_request()
            req = reflection_pb2.ServerReflectionRequest(file_containing_symbol=service)
            try:
                replies = stub.ServerReflectionInfo(iter([req]), timeout=timeout, metadata=call_metadata)
                for reply in replies:
                    if not reply.HasField("file_descriptor_response"):
                        continue
                    for raw in reply.file_descriptor_response.file_descriptor_proto:
                        descriptor = descriptor_pb2.FileDescriptorProto.FromString(raw)
                        if descriptor.name:
                            files.add(descriptor.name)
            except grpc.RpcError:
                continue
        inventory.descriptor_files = sorted(files)[:500]
    except Exception as exc:
        inventory.error = str(exc)[:1000]
    finally:
        channel.close()
    return inventory
