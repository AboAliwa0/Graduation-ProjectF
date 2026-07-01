from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from services.graphql_support import inspect_graphql_schema
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import error_result, make_result

meta = {
    "name": "GraphQL Schema Inventory",
    "severity": "Low",
    "description": "Safely inventories GraphQL root operations and schema metadata through standard introspection.",
    "category": "API Security",
}
inputs = [
    {
        "name": "endpoint",
        "label": "GraphQL endpoint",
        "type": "url",
        "required": True,
        "placeholder": "https://target.example/graphql",
        "help": "Explicit authorized endpoint required. No application queries or mutations are executed.",
    }
]


def _safe_endpoint(value: str) -> str:
    parsed = urlparse(value)
    sensitive = {"authorization", "api_key", "apikey", "access_token", "token", "secret", "password", "session"}
    query = [
        (key, "<redacted>" if key.lower() in sensitive else item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def scan(url, endpoint=""):
    target = str(endpoint or "").strip()
    if not target:
        return make_result(
            False,
            "An explicit GraphQL endpoint is required.",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={
                "endpoint": "",
                "introspection_status": "not_tested",
                "type_count": 0,
                "query_count": 0,
                "safe_probe_result": "missing_endpoint",
            },
            endpoint=url,
            requests_made=0,
        )
    runtime = current_runtime()
    started = runtime.request_count if runtime is not None else 0
    try:
        inventory = inspect_graphql_schema(target)
        artifact = inventory.to_dict()
        artifact["endpoint"] = _safe_endpoint(inventory.endpoint)
        if runtime is not None:
            runtime.artifacts["graphql"] = artifact
        query_count = len(inventory.operation_fields.get("query", []))
        evidence = {
            "endpoint": artifact["endpoint"],
            "introspection_status": "enabled" if inventory.introspection_enabled else "not_confirmed",
            "type_count": len(inventory.types),
            "query_count": query_count,
            "safe_probe_result": {
                "status_code": inventory.status_code,
                "errors": inventory.errors[:20],
            },
            "status_code": inventory.status_code,
            "query_type": inventory.query_type,
            "mutation_type": inventory.mutation_type,
            "subscription_type": inventory.subscription_type,
            "operation_fields": inventory.operation_fields,
        }
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 1
        if inventory.introspection_enabled:
            return make_result(
                True,
                "Unauthenticated GraphQL introspection is enabled. This is schema exposure rather than proof of broken authorization.",
                severity="Low",
                confidence="High",
                status="potential",
                evidence=evidence,
                recommendation="Restrict introspection in production when unnecessary, apply query depth/complexity controls, and enforce field- and object-level authorization independently of schema visibility.",
                endpoint=artifact["endpoint"],
                cwe="CWE-200",
                cvss=3.1,
                requests_made=requests_made,
            )
        return make_result(
            False,
            "GraphQL introspection was not confirmed.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=artifact["endpoint"],
            cwe="CWE-200",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except ValueError as exc:
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 0
        return make_result(
            False,
            f"GraphQL endpoint is invalid: {exc}",
            severity="Info",
            confidence="High",
            status="inconclusive",
            evidence={
                "endpoint": _safe_endpoint(target),
                "introspection_status": "not_tested",
                "safe_probe_result": "invalid_endpoint",
            },
            endpoint=_safe_endpoint(target),
            requests_made=requests_made,
        )
    except Exception as exc:
        requests_made = max(0, runtime.request_count - started) if runtime is not None else 1
        return error_result(f"GraphQL inventory failed: {exc}", endpoint=_safe_endpoint(target), requests_made=requests_made)
