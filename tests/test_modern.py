from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import grpc
import pytest
from google.protobuf import descriptor_pb2, descriptor_pool
from grpc_reflection.v1alpha import reflection
from websockets.sync.server import serve

from services.api_discovery import fetch_openapi_inventory, probe_safe_operations
from services.browser_crawler import BrowserUnavailable, crawl_spa
from services.grpc_support import _safe_metadata, inspect_grpc_reflection
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, ScanRuntime, activate_runtime
from services.websocket_support import _safe_response_headers, inspect_websocket
from vulnerabilities import authorization_matrix_scanner, graphql_scanner, grpc_scanner, modern_spa_scanner, oidc_scanner, openapi_scanner, websocket_scanner


def test_real_browser_crawls_spa_and_records_fetch(lab_server):
    runtime = ScanRuntime(scan_id=5001, user_id=1, request_budget=80, allow_private=True)
    with activate_runtime(runtime):
        inventory = crawl_spa(lab_server + "/modern/", max_pages=3, navigation_timeout_ms=8000)
    assert lab_server + "/modern/" in inventory.pages_visited
    assert any("/modern/settings" in item for item in inventory.pages_visited)
    assert any(item.resource_type in {"xhr", "fetch"} and "/modern/api/profile" in item.url for item in inventory.requests)
    assert "React" in inventory.framework_hints
    assert runtime.request_count > 0


def test_modern_spa_scanner_persists_artifact(lab_server):
    runtime = ScanRuntime(scan_id=5002, user_id=1, request_budget=80, allow_private=True)
    with activate_runtime(runtime):
        result = modern_spa_scanner.scan(lab_server + "/modern/", max_pages="2")
    assert result["status"] == "not_vulnerable", result
    assert result["requests_made"] > 0
    assert "browser" in runtime.artifacts
    assert runtime.artifacts["browser"]["pages_visited"]


def test_modern_spa_invalid_limits_and_browser_unavailable_are_inconclusive(monkeypatch, lab_server):
    invalid_pages = modern_spa_scanner.scan(lab_server + "/modern/", max_pages="many")
    invalid_timeout = modern_spa_scanner.scan(lab_server + "/modern/", navigation_timeout_ms="fast")
    assert invalid_pages["status"] == "inconclusive" and invalid_pages["requests_made"] == 0
    assert invalid_timeout["status"] == "inconclusive" and invalid_timeout["requests_made"] == 0

    def unavailable(*args, **kwargs):
        raise BrowserUnavailable("Chromium is unavailable for this test.")

    monkeypatch.setattr(modern_spa_scanner, "crawl_spa", unavailable)
    result = modern_spa_scanner.scan(lab_server + "/modern/")
    assert result["status"] == "inconclusive"
    assert result["evidence"]["browser_available"] is False


def test_modern_spa_artifact_redacts_secret_state_and_url_values():
    payload = modern_spa_scanner._sanitize_browser_payload(
        {
            "storage_state": {"cookies": [{"value": "raw-secret"}]},
            "requests": [{"url": "https://example.test/api?access_token=raw-secret&view=1"}],
            "console_errors": ["failed https://example.test/?api_key=raw-secret"],
        }
    )
    assert payload["storage_state"] == "<redacted>"
    assert "raw-secret" not in str(payload)
    assert payload["requests"][0]["url"].endswith("access_token=%3Credacted%3E&view=1")


def test_openapi_31_inventory_and_safe_probes(lab_server):
    runtime = ScanRuntime(scan_id=5003, user_id=1, request_budget=50, allow_private=True)
    with activate_runtime(runtime):
        inventory = fetch_openapi_inventory(lab_server + "/openapi.json", target_url=lab_server)
        observations = probe_safe_operations(inventory, max_operations=10)
    assert inventory.version == "3.1.0"
    assert len(inventory.operations) == 2
    assert {item["status"] for item in observations} == {200}


def test_openapi_scanner_flags_contract_warning_and_saves_inventory(lab_server):
    runtime = ScanRuntime(scan_id=5004, user_id=1, request_budget=50, allow_private=True)
    with activate_runtime(runtime):
        result = openapi_scanner.scan(lab_server, document_url=lab_server + "/openapi.json", probe_limit="10")
    assert result["vulnerable"] is True
    assert result["status"] == "potential"
    assert result["requests_made"] == runtime.request_count
    assert result["evidence"]["safe_probe_summary"]["read_only_methods_only"] is True
    assert "openapi" in runtime.artifacts
    assert runtime.artifacts["openapi"]["version"] == "3.1.0"


def test_openapi_invalid_limit_and_document_are_inconclusive(lab_server):
    invalid_limit = openapi_scanner.scan(lab_server, document_url=lab_server + "/openapi.json", probe_limit="many")
    assert invalid_limit["status"] == "inconclusive"
    assert invalid_limit["requests_made"] == 0

    runtime = ScanRuntime(scan_id=5016, user_id=1, request_budget=10, allow_private=True)
    with activate_runtime(runtime):
        invalid_document = openapi_scanner.scan(lab_server, document_url=lab_server + "/safe/headers")
    assert invalid_document["status"] == "inconclusive"
    assert invalid_document["requests_made"] == 1


def test_openapi_artifact_redacts_secret_examples():
    artifact = openapi_scanner._sanitize_openapi_artifact(
        {
            "source_url": "https://example.test/openapi.json?token=raw-token",
            "server_urls": ["https://example.test/?api_key=raw-key"],
            "operations": [
                {
                    "parameters": [
                        {"name": "api_key", "sample": "raw-api-key"},
                        {"name": "profile", "sample": {"password": "raw-password", "label": "safe"}},
                    ]
                }
            ],
            "safe_probe_observations": [],
        }
    )
    assert "raw-token" not in str(artifact)
    assert "raw-key" not in str(artifact)
    assert "raw-api-key" not in str(artifact)
    assert "raw-password" not in str(artifact)
    assert artifact["operations"][0]["parameters"][1]["sample"]["label"] == "safe"


def test_graphql_full_schema_inventory(lab_server):
    runtime = ScanRuntime(scan_id=5005, user_id=1, request_budget=20, allow_private=True)
    with activate_runtime(runtime):
        result = graphql_scanner.scan(lab_server, endpoint=lab_server + "/graphql-modern")
    assert result["status"] == "potential"
    assert result["requests_made"] == 1
    assert result["evidence"]["introspection_status"] == "enabled"
    assert result["evidence"]["query_count"] == 1
    assert result["evidence"]["query_type"] == "Query"
    assert "updateProfile" in result["evidence"]["operation_fields"]["mutation"]
    assert runtime.artifacts["graphql"]["introspection_enabled"] is True


def test_graphql_requires_explicit_endpoint(lab_server):
    result = graphql_scanner.scan(lab_server)
    assert result["status"] == "inconclusive"
    assert result["requests_made"] == 0
    assert result["evidence"]["safe_probe_result"] == "missing_endpoint"


def test_authorization_matrix_detects_potential_parity(lab_server):
    runtime = ScanRuntime(
        scan_id=5006,
        user_id=1,
        request_budget=30,
        allow_private=True,
        ephemeral={
            "auth_profiles": [
                {"name": "user", "expected_access": "user", "headers": {"Authorization": "Bearer low-role"}, "cookies": {}},
                {"name": "admin", "expected_access": "admin", "headers": {"Authorization": "Bearer high-role"}, "cookies": {}},
            ]
        },
    )
    with activate_runtime(runtime):
        result = authorization_matrix_scanner.scan(lab_server, endpoints="/roles/admin-vuln", max_endpoints="5")
    assert result["status"] == "potential", result
    assert result["severity"] == "High"
    assert result["requests_made"] == 2
    assert "low-role" not in str(result) and "high-role" not in str(result)
    assert runtime.artifacts["authorization_matrix"]["observations"]


def test_authorization_matrix_accepts_role_separation(lab_server):
    runtime = ScanRuntime(
        scan_id=5007,
        user_id=1,
        request_budget=30,
        allow_private=True,
        ephemeral={
            "auth_profiles": [
                {"name": "user", "expected_access": "user", "headers": {"Authorization": "Bearer low-role"}, "cookies": {}},
                {"name": "admin", "expected_access": "admin", "headers": {"Authorization": "Bearer high-role"}, "cookies": {}},
            ]
        },
    )
    with activate_runtime(runtime):
        result = authorization_matrix_scanner.scan(lab_server, endpoints="/roles/admin-safe", max_endpoints="5")
    assert result["status"] == "not_vulnerable", result


def test_authorization_matrix_rejects_invalid_limit_and_profiles(lab_server):
    runtime = ScanRuntime(
        scan_id=5014,
        user_id=1,
        request_budget=30,
        allow_private=True,
        ephemeral={"auth_profiles": ["invalid", {"expected_access": "admin", "headers": []}]},
    )
    with activate_runtime(runtime):
        invalid_limit = authorization_matrix_scanner.scan(lab_server, endpoints="/roles/admin-vuln", max_endpoints="many")
        invalid_profiles = authorization_matrix_scanner.scan(lab_server, endpoints="/roles/admin-vuln", max_endpoints="5")
    assert invalid_limit["status"] == "inconclusive" and invalid_limit["requests_made"] == 0
    assert invalid_profiles["status"] == "inconclusive" and invalid_profiles["requests_made"] == 0


def test_authorization_matrix_requires_distinct_role_levels(lab_server):
    runtime = ScanRuntime(
        scan_id=5015,
        user_id=1,
        request_budget=30,
        allow_private=True,
        ephemeral={
            "auth_profiles": [
                {"expected_access": "low", "headers": {"Authorization": "Bearer first"}},
                {"expected_access": "user", "headers": {"Authorization": "Bearer second"}},
            ]
        },
    )
    with activate_runtime(runtime):
        result = authorization_matrix_scanner.scan(lab_server, endpoints="/roles/admin-vuln", max_endpoints="5")
    assert result["status"] == "inconclusive"
    assert result["requests_made"] == 0


@pytest.fixture
def websocket_server():
    def handler(connection):
        connection.recv(timeout=0.5) if False else None
        connection.close()

    server = serve(handler, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.socket.getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/socket"
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_websocket_handshake_inventory(websocket_server):
    http_target = websocket_server.replace("ws://", "http://").rsplit("/", 1)[0]
    runtime = ScanRuntime(scan_id=5008, user_id=1, request_budget=10, allow_private=True)
    with activate_runtime(runtime):
        inventory = inspect_websocket(websocket_server, target_url=http_target)
    assert inventory.connected is True, inventory
    assert runtime.request_count == 1


def test_websocket_scanner_does_not_call_connectivity_a_vulnerability(websocket_server):
    http_target = websocket_server.replace("ws://", "http://").rsplit("/", 1)[0]
    runtime = ScanRuntime(scan_id=5009, user_id=1, request_budget=10, allow_private=True)
    with activate_runtime(runtime):
        result = websocket_scanner.scan(http_target, endpoint=websocket_server)
    assert result["status"] == "not_vulnerable", result
    assert result["requests_made"] == 1
    assert runtime.artifacts["websockets"][0]["connected"] is True


def test_websocket_requires_endpoint_and_redacts_sensitive_headers(lab_server):
    missing = websocket_scanner.scan(lab_server)
    assert missing["status"] == "inconclusive"
    assert missing["requests_made"] == 0

    headers = _safe_response_headers(
        {
            "Set-Cookie": "session=raw-secret",
            "Authorization": "Bearer raw-secret",
            "X-Access-Token": "raw-secret",
            "X-Trace": "safe-value",
        }
    )
    assert headers == {"X-Trace": "safe-value"}


@pytest.fixture
def grpc_reflection_server():
    pool = descriptor_pool.DescriptorPool()
    file_proto = descriptor_pb2.FileDescriptorProto()
    file_proto.name = "modern_lab.proto"
    file_proto.package = "lab"
    file_proto.syntax = "proto3"
    req = file_proto.message_type.add(); req.name = "PingRequest"
    res = file_proto.message_type.add(); res.name = "PingResponse"
    field = res.field.add(); field.name = "message"; field.number = 1; field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL; field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    service = file_proto.service.add(); service.name = "ModernService"
    method = service.method.add(); method.name = "Ping"; method.input_type = ".lab.PingRequest"; method.output_type = ".lab.PingResponse"
    pool.Add(file_proto)

    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    generic = grpc.method_handlers_generic_handler(
        "lab.ModernService",
        {
            "Ping": grpc.unary_unary_rpc_method_handler(
                lambda request, context: b"\x0a\x04pong",
                request_deserializer=lambda raw: raw,
                response_serializer=lambda raw: raw,
            )
        },
    )
    server.add_generic_rpc_handlers((generic,))
    service_names = ("lab.ModernService", reflection.SERVICE_NAME)
    reflection.enable_server_reflection(service_names, server, pool=pool)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        server.stop(grace=0).wait(timeout=3)


def test_grpc_reflection_real_server(grpc_reflection_server):
    runtime = ScanRuntime(scan_id=5010, user_id=1, request_budget=20, allow_private=True)
    with activate_runtime(runtime):
        inventory = inspect_grpc_reflection(grpc_reflection_server, tls=False)
    assert inventory.reflection_available is True, inventory
    assert "lab.ModernService" in inventory.services
    assert "modern_lab.proto" in inventory.descriptor_files
    assert runtime.request_count >= 2


def test_grpc_scanner_inventory_is_potential_and_counts_requests(grpc_reflection_server):
    runtime = ScanRuntime(scan_id=5017, user_id=1, request_budget=20, allow_private=True)
    with activate_runtime(runtime):
        result = grpc_scanner.scan("http://example.test", target=grpc_reflection_server, tls=False)
    assert result["status"] == "potential"
    assert result["requests_made"] == runtime.request_count
    assert result["evidence"]["reflection_status"] == "available"


def test_grpc_missing_invalid_target_and_metadata_redaction():
    missing = grpc_scanner.scan("http://example.test")
    invalid = grpc_scanner.scan("http://example.test", target="invalid", tls=False)
    assert missing["status"] == "inconclusive" and missing["requests_made"] == 0
    assert invalid["status"] == "inconclusive" and invalid["requests_made"] == 0
    assert _safe_metadata(
        {
            "Authorization": "Bearer raw-secret",
            "Cookie": "session=raw-secret",
            "X-Api-Token": "raw-secret",
            "X-Trace": "safe-value",
        }
    ) == (("X-Trace", "safe-value"),)


def test_grpc_budget_and_cancellation_propagate_inside_reflection(grpc_reflection_server):
    budget_runtime = ScanRuntime(scan_id=5018, user_id=1, request_budget=1, allow_private=True)
    with activate_runtime(budget_runtime), pytest.raises(RequestBudgetExceeded):
        inspect_grpc_reflection(grpc_reflection_server, tls=False)

    checks = iter((False, True))
    cancel_runtime = ScanRuntime(
        scan_id=5019,
        user_id=1,
        request_budget=20,
        allow_private=True,
        cancel_checker=lambda: next(checks, True),
    )
    with activate_runtime(cancel_runtime), pytest.raises(ScanCancelled):
        inspect_grpc_reflection(grpc_reflection_server, tls=False)


def test_oidc_secure_metadata_inventory(lab_server):
    runtime = ScanRuntime(scan_id=5011, user_id=1, request_budget=10, allow_private=True)
    with activate_runtime(runtime):
        result = oidc_scanner.scan(lab_server, discovery_url=lab_server + "/oidc-safe")
    assert result["status"] == "not_vulnerable", result
    assert result["requests_made"] == 1
    assert result["evidence"]["pkce_support"] == ["S256"]
    assert runtime.artifacts["oidc"]["code_challenge_methods_supported"] == ["S256"]


def test_oidc_unsigned_algorithm_is_flagged(lab_server):
    runtime = ScanRuntime(scan_id=5012, user_id=1, request_budget=10, allow_private=True)
    with activate_runtime(runtime):
        result = oidc_scanner.scan(lab_server, discovery_url=lab_server + "/oidc-risky")
    assert result["status"] == "potential", result
    assert result["severity"] == "High"
    assert result["requests_made"] == 1
    assert "none" in {item.lower() for item in result["evidence"]["id_token_signing_alg_values_supported"]}


def test_oidc_missing_document_is_inconclusive(lab_server):
    runtime = ScanRuntime(scan_id=5020, user_id=1, request_budget=10, allow_private=True)
    with activate_runtime(runtime):
        result = oidc_scanner.scan(lab_server, discovery_url=lab_server + "/missing-oidc")
    assert result["status"] == "inconclusive"
    assert result["requests_made"] == 1


def test_openapi_32_document_is_supported(lab_server):
    runtime = ScanRuntime(scan_id=5013, user_id=1, request_budget=20, allow_private=True)
    with activate_runtime(runtime):
        inventory = fetch_openapi_inventory(lab_server + "/openapi32.json", target_url=lab_server)
    assert inventory.version == "3.2.0"
    assert inventory.operations[0].operation_id == "getProfile32"
