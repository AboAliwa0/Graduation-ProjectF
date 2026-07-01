from __future__ import annotations

from services.grpc_support import GrpcAssessmentError, inspect_grpc_reflection
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import error_result, make_result

meta = {
    "name": "gRPC Reflection Inventory",
    "severity": "Low",
    "description": "Inventories gRPC services through the standard reflection API without invoking application methods.",
    "category": "API Security",
}
inputs = [
    {"name": "target", "label": "gRPC host:port", "type": "text", "required": True, "placeholder": "api.example.com:443", "help": "Reflection only; application RPC methods are not called."},
    {"name": "tls", "label": "Use TLS", "type": "boolean", "required": False, "help": "Enabled by default."},
]


def scan(url, target="", tls=True):
    target = str(target or "").strip()
    if not target:
        return make_result(
            False,
            "No gRPC target was supplied.",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"target": "", "reflection_status": "not_tested", "reason": "missing_target"},
            endpoint=url,
            requests_made=0,
        )
    runtime = current_runtime()
    started = runtime.request_count if runtime is not None else 0
    try:
        use_tls = not (tls is False or str(tls).lower() in {"0", "false", "no", "off"})
        inventory = inspect_grpc_reflection(target, tls=use_tls, metadata=(runtime.default_headers if runtime else {}))
        descriptor_requests = len([service for service in inventory.services[:100] if not service.startswith("grpc.reflection.")])
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 1 + descriptor_requests
        evidence = {
            **inventory.to_dict(),
            "reflection_status": "available" if inventory.reflection_available else "not_available",
            "service_count": len(inventory.services),
            "descriptor_file_count": len(inventory.descriptor_files),
        }
        if runtime is not None:
            runtime.artifacts["grpc"] = evidence
        if inventory.reflection_available:
            return make_result(
                True,
                "gRPC server reflection is enabled. This is an inventory exposure rather than a standalone compromise and should be assessed against the deployment threat model.",
                severity="Low",
                confidence="High",
                status="potential",
                evidence=evidence,
                recommendation="Restrict reflection to trusted administrative networks or authenticated development environments when public schema discovery is unnecessary.",
                endpoint=target,
                cwe="CWE-200",
                cvss=3.1,
                requests_made=requests_made,
            )
        return make_result(
            False,
            "gRPC reflection was not confirmed.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=target,
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except GrpcAssessmentError as exc:
        return make_result(
            False,
            str(exc),
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"target": target, "reflection_status": "not_tested"},
            endpoint=target,
            requests_made=max(0, runtime.request_count - started) if runtime is not None else 0,
        )
    except Exception as exc:
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 0
        return error_result(f"gRPC reflection assessment failed: {exc}", endpoint=target, requests_made=requests_made)
