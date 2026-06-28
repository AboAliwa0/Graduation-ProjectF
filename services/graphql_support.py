from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any

from vulnerabilities.common import safe_request

INTROSPECTION_QUERY = """
query CyberScanSchemaInventory {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        isDeprecated
        args { name type { kind name ofType { kind name } } }
        type { kind name ofType { kind name } }
      }
    }
  }
}
""".strip()


@dataclass(slots=True)
class GraphQLInventory:
    endpoint: str
    introspection_enabled: bool
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    types: list[dict[str, Any]] = field(default_factory=list)
    operation_fields: dict[str, list[str]] = field(default_factory=dict)
    errors: list[Any] = field(default_factory=list)
    status_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def inspect_graphql_schema(endpoint: str) -> GraphQLInventory:
    response = safe_request("POST", endpoint, json={"query": INTROSPECTION_QUERY, "operationName": "CyberScanSchemaInventory"})
    try:
        payload = response.json()
    except ValueError:
        return GraphQLInventory(endpoint=response.url, introspection_enabled=False, status_code=response.status_code, errors=["Non-JSON response"])
    data = payload.get("data") if isinstance(payload, dict) else None
    schema = data.get("__schema") if isinstance(data, dict) else None
    errors = payload.get("errors", []) if isinstance(payload, dict) else []
    if not isinstance(schema, dict):
        return GraphQLInventory(endpoint=response.url, introspection_enabled=False, status_code=response.status_code, errors=errors[:20])
    types = []
    raw_types = schema.get("types") or []
    for item in raw_types[:500]:
        if not isinstance(item, dict) or str(item.get("name") or "").startswith("__"):
            continue
        fields = []
        for field in (item.get("fields") or [])[:200]:
            if isinstance(field, dict):
                fields.append({
                    "name": str(field.get("name") or "")[:200],
                    "deprecated": bool(field.get("isDeprecated")),
                    "arg_names": [str(arg.get("name") or "")[:100] for arg in (field.get("args") or [])[:50] if isinstance(arg, dict)],
                })
        types.append({"kind": item.get("kind"), "name": item.get("name"), "fields": fields})
    root_names = {
        "query": str((schema.get("queryType") or {}).get("name") or ""),
        "mutation": str((schema.get("mutationType") or {}).get("name") or ""),
        "subscription": str((schema.get("subscriptionType") or {}).get("name") or ""),
    }
    by_name = {str(item.get("name")): item for item in types}
    operation_fields = {
        role: [str(field.get("name")) for field in (by_name.get(name, {}).get("fields") or [])]
        for role, name in root_names.items() if name
    }
    return GraphQLInventory(
        endpoint=response.url,
        introspection_enabled=True,
        query_type=root_names["query"],
        mutation_type=root_names["mutation"],
        subscription_type=root_names["subscription"],
        types=types,
        operation_fields=operation_fields,
        errors=errors[:20],
        status_code=response.status_code,
    )
