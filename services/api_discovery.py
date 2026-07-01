from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import yaml

from vulnerabilities.common import body_text, safe_request, validate_target_url

SAFE_METHODS = {"get", "head", "options"}
HTTP_METHODS = SAFE_METHODS | {"post", "put", "patch", "delete", "trace"}
SENSITIVE_PATH_RE = re.compile(r"/(admin|internal|debug|management|private|users?|accounts?|billing|payments?)(/|$)", re.I)
SENSITIVE_PARAMETER_RE = re.compile(r"(authorization|cookie|token|secret|password|api[-_]?key|credential|session)", re.I)
SECRET_SAMPLE_RE = re.compile(r"(bearer\s+\S+|eyJ[a-zA-Z0-9_-]{10,}\.|(?:sk|ghp|glpat|xox[baprs])[-_][a-zA-Z0-9_-]{8,})", re.I)


class OpenApiError(ValueError):
    pass


@dataclass(slots=True)
class ApiParameter:
    name: str
    location: str
    required: bool = False
    sample: Any = None


@dataclass(slots=True)
class ApiOperation:
    method: str
    path: str
    operation_id: str = ""
    summary: str = ""
    parameters: list[ApiParameter] = field(default_factory=list)
    security: Any = None
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["parameters"] = [asdict(item) for item in self.parameters]
        return payload


@dataclass(slots=True)
class OpenApiInventory:
    version: str
    title: str
    source_url: str
    server_urls: list[str]
    operations: list[ApiOperation]
    security_schemes: list[str]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "title": self.title,
            "source_url": self.source_url,
            "server_urls": self.server_urls,
            "security_schemes": self.security_schemes,
            "warnings": self.warnings,
            "operations": [item.to_dict() for item in self.operations],
        }


def _load_document(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8", errors="ignore")) > 2_000_000:
        raise OpenApiError("OpenAPI document exceeds the 2 MB safety limit.")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        try:
            payload = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise OpenApiError(f"OpenAPI document is not valid JSON or YAML: {exc}") from exc
    if not isinstance(payload, dict):
        raise OpenApiError("OpenAPI document must be an object.")
    return payload


def _pointer(document: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise OpenApiError("External OpenAPI references are disabled for safety.")
    current: Any = document
    for raw in reference[2:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise OpenApiError(f"Unresolvable local reference: {reference}")
        current = current[part]
    return current


def _resolve(document: dict[str, Any], value: Any, *, seen: set[str] | None = None) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    reference = str(value["$ref"])
    seen = set(seen or ())
    if reference in seen:
        raise OpenApiError(f"Reference cycle detected at {reference}")
    seen.add(reference)
    resolved = _pointer(document, reference)
    return _resolve(document, resolved, seen=seen)


def _sample_from_schema(document: dict[str, Any], schema: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return None
    schema = _resolve(document, schema or {})
    if not isinstance(schema, dict):
        return None
    for key in ("example", "default", "const"):
        if key in schema:
            return schema[key]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    kind = schema.get("type")
    fmt = schema.get("format")
    if kind == "integer":
        return int(schema.get("minimum", 1))
    if kind == "number":
        return float(schema.get("minimum", 1.0))
    if kind == "boolean":
        return True
    if kind == "array":
        item = _sample_from_schema(document, schema.get("items", {}), depth=depth + 1)
        return [] if item is None else [item]
    if kind == "object" or isinstance(schema.get("properties"), dict):
        return {
            str(name): _sample_from_schema(document, child, depth=depth + 1)
            for name, child in list((schema.get("properties") or {}).items())[:30]
        }
    if fmt in {"uuid"}:
        return "00000000-0000-4000-8000-000000000001"
    if fmt in {"date"}:
        return "2026-01-01"
    if fmt in {"date-time"}:
        return "2026-01-01T00:00:00Z"
    if fmt in {"email"}:
        return "authorized-test@example.invalid"
    return "cyberscan-sample"


def _operation_parameters(document: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]) -> list[ApiParameter]:
    raw_parameters: list[Any] = []
    raw_parameters.extend(path_item.get("parameters") or [])
    raw_parameters.extend(operation.get("parameters") or [])
    result: list[ApiParameter] = []
    seen: set[tuple[str, str]] = set()
    for raw in raw_parameters[:100]:
        param = _resolve(document, raw)
        if not isinstance(param, dict):
            continue
        name = str(param.get("name") or "")[:120]
        location = str(param.get("in") or "")[:30]
        if not name or not location or (name, location) in seen:
            continue
        seen.add((name, location))
        schema = param.get("schema") or {}
        sample = param.get("example", _sample_from_schema(document, schema))
        result.append(ApiParameter(name=name, location=location, required=bool(param.get("required")), sample=sample))
    return result


def parse_openapi_document(document: dict[str, Any], *, source_url: str, target_url: str) -> OpenApiInventory:
    version = str(document.get("openapi") or document.get("swagger") or "")
    if not (version.startswith("3.") or version == "2.0"):
        raise OpenApiError("Supported OpenAPI versions are 2.0 and 3.x.")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    title = str(info.get("title") or "Untitled API")[:200]
    warnings: list[str] = []

    server_urls: list[str] = []
    if version == "2.0":
        scheme = ((document.get("schemes") or [urlparse(target_url).scheme])[0])
        host = document.get("host") or urlparse(target_url).netloc
        base_path = document.get("basePath") or "/"
        server_urls = [f"{scheme}://{host}{base_path}".rstrip("/")]
        schemes = (document.get("securityDefinitions") or {})
    else:
        for server in (document.get("servers") or [])[:20]:
            if isinstance(server, dict) and server.get("url"):
                raw = str(server["url"])
                if "{" in raw:
                    warnings.append(f"Server template was not expanded: {raw}")
                    continue
                server_urls.append(urljoin(source_url, raw).rstrip("/"))
        if not server_urls:
            server_urls = [target_url.rstrip("/")]
        components = document.get("components") if isinstance(document.get("components"), dict) else {}
        schemes = components.get("securitySchemes") or {}

    target_origin = (urlparse(target_url).scheme.lower(), (urlparse(target_url).hostname or "").lower(), urlparse(target_url).port)
    safe_servers: list[str] = []
    for raw in server_urls:
        try:
            normalized = validate_target_url(raw)
        except Exception:
            warnings.append(f"Ignored unsafe or invalid server URL: {raw}")
            continue
        parsed = urlparse(normalized)
        origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port)
        if origin != target_origin:
            warnings.append(f"Ignored cross-origin server URL: {raw}")
            continue
        safe_servers.append(normalized.rstrip("/"))
    if not safe_servers:
        safe_servers = [target_url.rstrip("/")]

    operations: list[ApiOperation] = []
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise OpenApiError("OpenAPI document has no paths object.")
    global_security = document.get("security")
    for path, raw_path_item in list(paths.items())[:2000]:
        path_item = _resolve(document, raw_path_item)
        if not isinstance(path_item, dict):
            continue
        for method, raw_operation in path_item.items():
            method_l = str(method).lower()
            if method_l not in HTTP_METHODS or not isinstance(raw_operation, dict):
                continue
            operation = _resolve(document, raw_operation)
            if not isinstance(operation, dict):
                continue
            operations.append(
                ApiOperation(
                    method=method_l.upper(),
                    path=str(path)[:1000],
                    operation_id=str(operation.get("operationId") or "")[:200],
                    summary=str(operation.get("summary") or operation.get("description") or "")[:500],
                    parameters=_operation_parameters(document, path_item, operation),
                    security=operation.get("security", global_security),
                    tags=[str(item)[:80] for item in (operation.get("tags") or [])[:20]],
                    deprecated=bool(operation.get("deprecated")),
                )
            )
    if len(paths) > 2000:
        warnings.append("Only the first 2,000 paths were inventoried.")
    return OpenApiInventory(
        version=version,
        title=title,
        source_url=source_url,
        server_urls=safe_servers,
        operations=operations,
        security_schemes=sorted(str(key) for key in schemes.keys())[:100],
        warnings=warnings,
    )


def fetch_openapi_inventory(document_url: str, *, target_url: str) -> OpenApiInventory:
    target = validate_target_url(target_url)
    source = validate_target_url(urljoin(target, document_url))
    target_host = (urlparse(target).hostname or "").lower()
    source_host = (urlparse(source).hostname or "").lower()
    if source_host != target_host:
        raise OpenApiError("OpenAPI document must be hosted on the authorized target hostname.")
    response = safe_request("GET", source, allow_redirects=True)
    if response.status_code >= 400:
        raise OpenApiError(f"OpenAPI document returned HTTP {response.status_code}.")
    return parse_openapi_document(_load_document(body_text(response)), source_url=source, target_url=target)


def _safe_probe_sample(parameter: ApiParameter) -> Any:
    sample = parameter.sample
    if SENSITIVE_PARAMETER_RE.search(parameter.name):
        return "cyberscan-sample"
    if isinstance(sample, str) and SECRET_SAMPLE_RE.search(sample):
        return "cyberscan-sample"
    return sample


def _render_path(path: str, parameters: list[ApiParameter]) -> tuple[str, dict[str, Any], dict[str, str]]:
    rendered = path
    query: dict[str, Any] = {}
    headers: dict[str, str] = {}
    for param in parameters:
        sample = _safe_probe_sample(param)
        if sample is None and not param.required:
            continue
        if sample is None:
            sample = "cyberscan-sample"
        if param.location == "path":
            rendered = rendered.replace("{" + param.name + "}", quote(str(sample), safe=""))
        elif param.location == "query":
            query[param.name] = sample
        elif param.location == "header" and param.name.lower() not in {"host", "content-length", "authorization", "cookie"}:
            headers[param.name] = str(sample)
    return rendered, query, headers


def probe_safe_operations(inventory: OpenApiInventory, *, max_operations: int = 40) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    base = inventory.server_urls[0].rstrip("/") if inventory.server_urls else ""
    for operation in inventory.operations:
        if operation.method.lower() not in SAFE_METHODS:
            continue
        if len(observations) >= max_operations:
            break
        rendered, query, headers = _render_path(operation.path, operation.parameters)
        endpoint = urljoin(base + "/", rendered.lstrip("/"))
        response = safe_request(operation.method, endpoint, params=query or None, headers=headers or None, allow_redirects=False)
        observations.append(
            {
                "method": operation.method,
                "path": operation.path,
                "endpoint": endpoint,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", "")[:200],
                "declared_security": operation.security,
                "sensitive_path": bool(SENSITIVE_PATH_RE.search(operation.path)),
            }
        )
    return observations


def authorization_declaration_findings(inventory: OpenApiInventory) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for operation in inventory.operations:
        if not SENSITIVE_PATH_RE.search(operation.path):
            continue
        if operation.security == [] or operation.security is None:
            findings.append(
                {
                    "method": operation.method,
                    "path": operation.path,
                    "operation_id": operation.operation_id,
                    "reason": "Sensitive-looking operation has no authentication requirement declared in the contract.",
                }
            )
    return findings[:100]
