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
        "required": False,
        "placeholder": "https://target.example/graphql",
        "help": "Leave empty to use the target URL. No application queries or mutations are executed.",
    }
]


def scan(url, endpoint=""):
    target = endpoint or url
    runtime = current_runtime()
    try:
        inventory = inspect_graphql_schema(target)
        artifact = inventory.to_dict()
        if runtime is not None:
            runtime.artifacts["graphql"] = artifact
        if inventory.introspection_enabled:
            evidence = {
                "status_code": inventory.status_code,
                "query_type": inventory.query_type,
                "mutation_type": inventory.mutation_type,
                "subscription_type": inventory.subscription_type,
                "operation_fields": inventory.operation_fields,
                "type_count": len(inventory.types),
            }
            return make_result(
                True,
                "Unauthenticated GraphQL introspection is enabled. This is schema exposure rather than proof of broken authorization.",
                severity="Low",
                confidence="High",
                status="potential",
                evidence=evidence,
                recommendation="Restrict introspection in production when unnecessary, apply query depth/complexity controls, and enforce field- and object-level authorization independently of schema visibility.",
                endpoint=inventory.endpoint,
                cwe="CWE-200",
                cvss=3.1,
            )
        return make_result(
            False,
            "GraphQL introspection was not confirmed.",
            severity="Info",
            confidence="High",
            evidence={"errors": inventory.errors, "status_code": inventory.status_code},
            endpoint=inventory.endpoint,
            cwe="CWE-200",
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"GraphQL inventory failed: {exc}", endpoint=target)
