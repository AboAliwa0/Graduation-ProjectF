from __future__ import annotations

import copy
import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from services.api_discovery import OpenApiError, authorization_declaration_findings, fetch_openapi_inventory, probe_safe_operations
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import error_result, make_result

meta = {
    "name": "OpenAPI Contract Discovery",
    "severity": "Low",
    "description": "Imports OpenAPI 2.0/3.x contracts, inventories operations, and safely probes read-only endpoints.",
    "category": "API Security",
}
inputs = [
    {"name": "document_url", "label": "OpenAPI document URL/path", "type": "url", "required": False, "placeholder": "/openapi.json", "help": "Must be hosted on the authorized target hostname."},
    {"name": "probe_limit", "label": "Read-only operation probe limit", "type": "number", "required": False, "placeholder": "30", "help": "Only GET, HEAD, and OPTIONS operations are sent."},
]

SENSITIVE_NAME_RE = re.compile(r"(authorization|cookie|token|secret|password|api[-_]?key|credential|session)", re.I)
SECRET_VALUE_RE = re.compile(r"(bearer\s+\S+|eyJ[a-zA-Z0-9_-]{10,}\.|(?:sk|ghp|glpat|xox[baprs])[-_][a-zA-Z0-9_-]{8,})", re.I)


def _request_count(runtime, started: int, fallback: int = 0) -> int:
    return max(0, runtime.request_count - started) if runtime is not None else fallback


def _redacted_sample(value: Any) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"<redacted:{digest}>"


def _sanitize_sample(value: Any, *, parameter_name: str = "") -> Any:
    if value is None:
        return None
    if SENSITIVE_NAME_RE.search(parameter_name):
        return _redacted_sample(value)
    if isinstance(value, dict):
        return {
            str(key): (_redacted_sample(item) if SENSITIVE_NAME_RE.search(str(key)) else _sanitize_sample(item, parameter_name=str(key)))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_sample(item, parameter_name=parameter_name) for item in value[:100]]
    if isinstance(value, str) and SECRET_VALUE_RE.search(value):
        return _redacted_sample(value)
    return value


def _sanitize_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        query = [
            (key, "<redacted>" if SENSITIVE_NAME_RE.search(key) or SECRET_VALUE_RE.search(item) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
    except Exception:
        return SECRET_VALUE_RE.sub("<redacted>", value)


def _sanitize_openapi_artifact(payload: dict[str, Any]) -> dict[str, Any]:
    clean = copy.deepcopy(payload)
    clean["source_url"] = _sanitize_url(str(clean.get("source_url") or ""))
    clean["server_urls"] = [_sanitize_url(str(item)) for item in clean.get("server_urls", [])]
    for operation in clean.get("operations", []):
        if not isinstance(operation, dict):
            continue
        for parameter in operation.get("parameters", []):
            if not isinstance(parameter, dict) or "sample" not in parameter:
                continue
            parameter["sample"] = _sanitize_sample(parameter.get("sample"), parameter_name=str(parameter.get("name") or ""))
    for observation in clean.get("safe_probe_observations", []):
        if isinstance(observation, dict) and observation.get("endpoint"):
            observation["endpoint"] = _sanitize_url(str(observation["endpoint"]))
    return clean


def scan(url, document_url="/openapi.json", probe_limit="30"):
    runtime = current_runtime()
    started = runtime.request_count if runtime is not None else 0
    try:
        parsed_probe_limit = int(30 if probe_limit in (None, "") else probe_limit)
    except (TypeError, ValueError):
        return make_result(
            False,
            "OpenAPI probe limit must be a valid integer.",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"document_url": document_url or "/openapi.json", "probe_limit": str(probe_limit)},
            endpoint=document_url or url,
            requests_made=0,
        )
    if not 0 <= parsed_probe_limit <= 100:
        return make_result(
            False,
            "OpenAPI probe limit must be between 0 and 100.",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"document_url": document_url or "/openapi.json", "probe_limit": parsed_probe_limit},
            endpoint=document_url or url,
            requests_made=0,
        )
    try:
        inventory = fetch_openapi_inventory(document_url or "/openapi.json", target_url=url)
        observations = probe_safe_operations(inventory, max_operations=parsed_probe_limit)
        declaration_findings = authorization_declaration_findings(inventory)
        artifact_payload = inventory.to_dict()
        artifact_payload["safe_probe_observations"] = observations
        artifact = _sanitize_openapi_artifact(artifact_payload)
        safe_observations = artifact["safe_probe_observations"]
        if runtime is not None:
            runtime.artifacts["openapi"] = artifact
        methods = {
            method: sum(op.method == method for op in inventory.operations)
            for method in sorted({op.method for op in inventory.operations})
        }
        status_counts: dict[str, int] = {}
        for observation in safe_observations:
            key = str(observation.get("status", "unknown"))
            status_counts[key] = status_counts.get(key, 0) + 1
        evidence = {
            "document_url": artifact["source_url"],
            "openapi_version": inventory.version,
            "endpoint_count": len(inventory.operations),
            "methods": methods,
            "safe_probe_summary": {
                "attempted": len(observations),
                "status_counts": status_counts,
                "read_only_methods_only": True,
            },
            "title": inventory.title,
            "version": inventory.version,
            "servers": artifact["server_urls"],
            "operation_count": len(inventory.operations),
            "method_counts": methods,
            "security_schemes": inventory.security_schemes,
            "safe_probes": safe_observations[:50],
            "warnings": inventory.warnings,
        }
        if declaration_findings:
            return make_result(
                True,
                "The API contract contains sensitive-looking operations without an authentication requirement declaration. This is a contract-level warning and requires runtime authorization validation.",
                severity="Low",
                confidence="Medium",
                status="potential",
                evidence={**evidence, "authorization_declaration_warnings": declaration_findings},
                recommendation="Declare authentication requirements in the OpenAPI contract and validate object/function authorization with separate low- and high-privilege test accounts.",
                endpoint=artifact["source_url"],
                cwe="CWE-284",
                cvss=3.1,
                requests_made=_request_count(runtime, started, 1 + len(observations)),
            )
        return make_result(
            False,
            f"Imported OpenAPI {inventory.version} and inventoried {len(inventory.operations)} operation(s); no contract-level authorization warning was identified.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=artifact["source_url"],
            requests_made=_request_count(runtime, started, 1 + len(observations)),
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except (OpenApiError, ValueError) as exc:
        return make_result(
            False,
            f"OpenAPI inventory was not available: {exc}",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={"document_url": _sanitize_url(document_url or "/openapi.json")},
            endpoint=_sanitize_url(document_url or url),
            requests_made=_request_count(runtime, started),
        )
    except Exception as exc:
        return error_result(
            f"OpenAPI assessment failed: {exc}",
            endpoint=_sanitize_url(document_url or url),
            requests_made=_request_count(runtime, started, 1),
        )
