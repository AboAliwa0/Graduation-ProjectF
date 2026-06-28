from __future__ import annotations

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


def scan(url, document_url="/openapi.json", probe_limit="30"):
    runtime = current_runtime()
    try:
        inventory = fetch_openapi_inventory(document_url or "/openapi.json", target_url=url)
        observations = probe_safe_operations(inventory, max_operations=max(0, min(int(probe_limit or 30), 100)))
        declaration_findings = authorization_declaration_findings(inventory)
        artifact = inventory.to_dict()
        artifact["safe_probe_observations"] = observations
        if runtime is not None:
            runtime.artifacts["openapi"] = artifact
        evidence = {
            "title": inventory.title,
            "version": inventory.version,
            "servers": inventory.server_urls,
            "operation_count": len(inventory.operations),
            "method_counts": {method: sum(op.method == method for op in inventory.operations) for method in sorted({op.method for op in inventory.operations})},
            "security_schemes": inventory.security_schemes,
            "safe_probes": observations[:50],
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
                endpoint=inventory.source_url,
                cwe="CWE-284",
                cvss=3.1,
            )
        return make_result(
            False,
            f"Imported OpenAPI {inventory.version} and inventoried {len(inventory.operations)} operation(s); no contract-level authorization warning was identified.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=inventory.source_url,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except OpenApiError as exc:
        return make_result(False, f"OpenAPI inventory was not available: {exc}", severity="Info", confidence="High", status="inconclusive", endpoint=document_url or url)
    except Exception as exc:
        return error_result(f"OpenAPI assessment failed: {exc}", endpoint=document_url or url)
