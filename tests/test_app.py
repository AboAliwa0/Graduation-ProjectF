import importlib
import os
import time


def _load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-flask-secret-abcdefghijklmnopqrstuvwxyz")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-abcdefghijklmnopqrstuvwxyz")
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    import database
    import app as app_module
    importlib.reload(database)
    app_module = importlib.reload(app_module)
    app_module.app.config.update(TESTING=True)
    return app_module


def _csrf(client, path="/login"):
    client.get(path)
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def test_registration_login_and_scanner_catalog(tmp_path, monkeypatch):
    app_module = _load_app(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    token = _csrf(client, "/register")
    response = client.post("/register", data={"email": "student@example.com", "password": "SecurePass123", "confirm_password": "SecurePass123", "csrf_token": token})
    assert response.status_code == 302
    token = _csrf(client, "/login")
    response = client.post("/login", data={"email": "student@example.com", "password": "SecurePass123", "csrf_token": token})
    assert response.status_code == 302
    catalog = client.get("/api/scanners")
    assert catalog.status_code == 200
    payload = catalog.get_json()
    assert len(payload["scanners"]) == 26
    assert all("inputs" in item for item in payload["scanners"])


def test_scan_requires_csrf_authorization_and_blocks_private_targets(tmp_path, monkeypatch):
    app_module = _load_app(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    token = _csrf(client, "/register")
    client.post("/register", data={"email": "student2@example.com", "password": "SecurePass123", "confirm_password": "SecurePass123", "csrf_token": token})
    token = _csrf(client, "/login")
    client.post("/login", data={"email": "student2@example.com", "password": "SecurePass123", "csrf_token": token})
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]

    assert client.post("/scan-live", json={"url": "http://127.0.0.1:1", "vulns": ["xss"], "authorized": True}).status_code == 400
    response = client.post("/scan-live", json={"url": "http://127.0.0.1:1", "vulns": ["xss"], "authorized": False}, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    response = client.post("/scan-live", json={"url": "http://127.0.0.1:1", "vulns": ["xss"], "authorized": True}, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    assert "Private" in response.get_json()["error"]


def test_scanner_input_urls_are_limited_to_target_origin_and_trusted_oast(tmp_path, monkeypatch, lab_server):
    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("OAST_ALLOW_PRIVATE_CALLBACKS", "true")
    monkeypatch.setenv("OAST_PUBLIC_BASE_URL", lab_server)
    client, csrf, _ = _register_and_login(app_module, "scanner-scope@example.com")
    submitted = []
    monkeypatch.setattr(app_module, "register_scan_runtime", lambda runtime: None)
    monkeypatch.setattr(app_module, "submit_scan_job", lambda *args, **kwargs: submitted.append(args))

    unrelated = lab_server.replace("127.0.0.1", "localhost") + "/safe/graphql"
    rejected = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/headers",
            "vulns": ["graphql_scanner"],
            "authorized": True,
            "scanner_inputs": {"graphql_scanner": {"endpoint": unrelated}},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert rejected.status_code == 400
    assert "same origin" in rejected.get_json()["error"].lower()
    assert not submitted

    allowed = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/headers",
            "vulns": ["graphql_scanner"],
            "authorized": True,
            "scanner_inputs": {"graphql_scanner": {"endpoint": "/safe/graphql"}},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert allowed.status_code == 202, allowed.get_data(as_text=True)
    assert submitted[-1][6]["scanner_inputs"]["graphql_scanner"]["endpoint"] == lab_server + "/safe/graphql"

    trusted = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/ssrf",
            "vulns": ["ssrf_scanner"],
            "authorized": True,
            "scanner_inputs": {"ssrf_scanner": {"param": "url", "callback_base_url": lab_server}},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert trusted.status_code == 202, trusted.get_data(as_text=True)

    untrusted = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/ssrf",
            "vulns": ["ssrf_scanner"],
            "authorized": True,
            "scanner_inputs": {"ssrf_scanner": {"param": "url", "callback_base_url": lab_server.replace("127.0.0.1", "localhost")}},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert untrusted.status_code == 400
    assert "trusted oast" in untrusted.get_json()["error"].lower()


def test_local_analysis_is_bounded_and_escapes_third_party_dependency(tmp_path, monkeypatch):
    app_module = _load_app(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    token = _csrf(client, "/register")
    client.post("/register", data={"email": "student3@example.com", "password": "SecurePass123", "confirm_password": "SecurePass123", "csrf_token": token})
    token = _csrf(client, "/login")
    client.post("/login", data={"email": "student3@example.com", "password": "SecurePass123", "csrf_token": token})
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    response = client.post("/ai-analysis", json={"scan_results": [{"name": "xss", "vulnerable": True, "status": "confirmed", "severity": "High", "result": "reflected", "confidence": "High"}]}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    assert response.get_json()["analysis_mode"] == "local_deterministic"


def test_end_to_end_authorized_local_scan(tmp_path, monkeypatch, lab_server):
    import time

    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    client = app_module.app.test_client()
    token = _csrf(client, "/register")
    client.post("/register", data={"email": "e2e@example.com", "password": "SecurePass123", "confirm_password": "SecurePass123", "csrf_token": token})
    token = _csrf(client, "/login")
    client.post("/login", data={"email": "e2e@example.com", "password": "SecurePass123", "csrf_token": token})
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    started = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/vuln/html",
            "vulns": ["xss"],
            "authorized": True,
            "scanner_inputs": {"xss": {"param": "q"}},
        },
        headers={"X-CSRF-Token": token},
    )
    assert started.status_code == 202, started.get_data(as_text=True)
    scan_id = started.get_json()["scan_id"]
    payload = None
    for _ in range(40):
        response = client.get(f"/scan-status/{scan_id}")
        assert response.status_code == 200
        payload = response.get_json()["scan"]
        if payload["status"] == "done":
            break
        time.sleep(0.05)
    assert payload and payload["status"] == "done", payload
    assert len(payload["results"]) == 1
    assert payload["results"][0]["name"] == "xss"
    assert payload["results"][0]["status"] == "confirmed"


def _register_and_login(app_module, email="pro@example.com"):
    client = app_module.app.test_client()
    token = _csrf(client, "/register")
    response = client.post(
        "/register",
        data={"email": email, "password": "SecurePass123", "confirm_password": "SecurePass123", "csrf_token": token},
    )
    assert response.status_code == 302
    token = _csrf(client, "/login")
    response = client.post(
        "/login",
        data={"email": email, "password": "SecurePass123", "csrf_token": token},
    )
    assert response.status_code == 302
    with client.session_transaction() as sess:
        csrf = sess["_csrf_token"]
        user_id = sess["user_id"]
    return client, csrf, user_id


def _wait_for_terminal_scan(client, scan_id, timeout_seconds=10.0, poll_interval=0.05):
    terminal_statuses = {"done", "failed", "cancelled", "budget_exhausted"}
    deadline = time.monotonic() + timeout_seconds
    payload = None
    while time.monotonic() < deadline:
        response = client.get(f"/scan-status/{scan_id}")
        assert response.status_code == 200
        payload = response.get_json()["scan"]
        if payload.get("status") in terminal_statuses:
            return payload
        time.sleep(poll_interval)

    payload = payload or {}
    artifacts = payload.get("artifacts")
    debug_info = {
        "status": payload.get("status"),
        "current_scanner": payload.get("current_scanner"),
        "progress": payload.get("progress"),
        "requests_made": payload.get("request_count", payload.get("requests_made")),
        "artifact_keys": sorted(artifacts.keys()) if isinstance(artifacts, dict) else [],
    }
    raise AssertionError(f"Scan {scan_id} did not finish within {timeout_seconds}s: {debug_info}")


def test_request_budget_is_hard_stop_and_credentials_are_not_persisted(tmp_path, monkeypatch, lab_server):
    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    client, csrf, _ = _register_and_login(app_module, "budget@example.com")
    secret = "Bearer never-store-this-secret"
    started = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/headers",
            "vulns": ["clickjacking_scanner", "cors_scanner", "csrf_scan", "dir_scan", "info_scan"],
            "authorized": True,
            "request_budget": 10,
            "http_headers": {"Authorization": secret},
            "cookies": {"session": "never-store-cookie"},
            "scanner_inputs": {"dir_scan": {"paths": "a/,b/,c/,d/,e/"}},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert started.status_code == 202, started.get_data(as_text=True)
    payload = _wait_for_terminal_scan(client, started.get_json()["scan_id"])
    assert payload["status"] == "budget_exhausted", payload
    assert payload["request_count"] == 10
    assert "never-store" not in str(payload)
    for path in tmp_path.iterdir():
        if path.is_file():
            assert b"never-store" not in path.read_bytes()


def test_forbidden_global_transport_headers_are_rejected(tmp_path, monkeypatch, lab_server):
    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    client, csrf, _ = _register_and_login(app_module, "headers@example.com")
    response = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/headers",
            "vulns": ["clickjacking_scanner"],
            "authorized": True,
            "http_headers": {"Host": "attacker.invalid"},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 400
    assert "not allowed" in response.get_json()["error"]


def test_required_scope_blocks_then_allows_authorized_host(tmp_path, monkeypatch, lab_server):
    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("REQUIRE_TARGET_SCOPE", "true")
    client, csrf, _ = _register_and_login(app_module, "scope@example.com")
    request_body = {
        "url": lab_server + "/safe/headers",
        "vulns": ["clickjacking_scanner"],
        "authorized": True,
    }
    blocked = client.post("/scan-live", json=request_body, headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 400
    assert "scope" in blocked.get_json()["error"].lower()

    created = client.post(
        "/api/scopes",
        json={"hostname": "127.0.0.1", "description": "isolated test lab"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201, created.get_data(as_text=True)
    allowed = client.post("/scan-live", json=request_body, headers={"X-CSRF-Token": csrf})
    assert allowed.status_code == 202, allowed.get_data(as_text=True)
    assert _wait_for_terminal_scan(client, allowed.get_json()["scan_id"])["status"] == "done"


def test_sarif_export_and_audit_log(tmp_path, monkeypatch):
    app_module = _load_app(tmp_path, monkeypatch)
    client, _, user_id = _register_and_login(app_module, "sarif@example.com")
    finding = {
        "name": "xss",
        "vulnerable": True,
        "status": "confirmed",
        "severity": "High",
        "confidence": "High",
        "result": "Reflected XSS confirmed in the authorized lab.",
        "evidence": {"marker": "safe-canary"},
        "endpoint": "https://example.com/search",
        "parameter": "q",
        "cwe": "CWE-79",
        "cvss": 8.2,
        "recommendation": "Encode output.",
    }
    conn = app_module.connect()
    cursor = conn.execute(
        "INSERT INTO scans (user_id,target,result,status,progress,risk_score,completed_at) VALUES (?,?,?,?,?,?,?)",
        (user_id, "https://example.com", __import__("json").dumps([finding]), "done", 100, 25.0, app_module.utc_now()),
    )
    scan_id = cursor.lastrowid
    conn.commit(); conn.close()

    details = client.get(f"/scan/{scan_id}")
    assert details.status_code == 200
    assert b"Risk / Security Score" in details.data
    pdf = client.get(f"/scan/{scan_id}/report")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    exported_json = client.get(f"/scan/{scan_id}/export-json")
    assert exported_json.status_code == 200

    response = client.get(f"/scan/{scan_id}/export-sarif")
    assert response.status_code == 200
    payload = __import__("json").loads(response.data)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "xss"
    assert payload["runs"][0]["results"][0]["properties"]["confidence"] == "High"
    tags = payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert any("ASVS 5.0" in tag for tag in tags)

    audit_response = client.get("/api/audit")
    assert audit_response.status_code == 200
    actions = {item["action"] for item in audit_response.get_json()["events"]}
    assert {"auth.register", "auth.login", "scan.export_sarif"}.issubset(actions)


def test_cancel_queued_scan_updates_state(tmp_path, monkeypatch):
    app_module = _load_app(tmp_path, monkeypatch)
    client, csrf, user_id = _register_and_login(app_module, "cancel@example.com")
    conn = app_module.connect()
    cursor = conn.execute(
        "INSERT INTO scans (user_id,target,result,status,selected_scanners) VALUES (?,?,?,?,?)",
        (user_id, "https://example.com", "[]", "queued", '["xss"]'),
    )
    scan_id = cursor.lastrowid
    conn.commit(); conn.close()
    response = client.post(
        f"/scan/{scan_id}/cancel",
        json={},
        headers={"X-CSRF-Token": csrf, "Accept": "application/json"},
    )
    assert response.status_code == 200
    status = client.get(f"/scan-status/{scan_id}").get_json()["scan"]
    assert status["status"] == "cancelled"


def test_end_to_end_modern_scan_artifacts_and_secret_redaction(tmp_path, monkeypatch, lab_server):
    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    client, csrf, _ = _register_and_login(app_module, "modern-e2e@example.com")
    low_secret = "Bearer low-secret-never-persist"
    high_secret = "Bearer high-secret-never-persist"
    started = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/modern/",
            "vulns": ["modern_spa_scanner", "openapi_scanner", "graphql_scanner", "authorization_matrix_scanner"],
            "authorized": True,
            "scan_mode": "modern",
            "request_budget": 120,
            "scanner_inputs": {
                "modern_spa_scanner": {"max_pages": "2", "navigation_timeout_ms": "8000"},
                "openapi_scanner": {"document_url": lab_server + "/openapi.json", "probe_limit": "10"},
                "graphql_scanner": {"endpoint": lab_server + "/graphql-modern"},
                "authorization_matrix_scanner": {"endpoints": "/roles/admin-vuln", "max_endpoints": "5"},
            },
            "auth_profiles": [
                {"name": "user", "expected_access": "user", "headers": {"Authorization": low_secret}},
                {"name": "admin", "expected_access": "admin", "headers": {"Authorization": high_secret}},
            ],
            "browser_storage_state": {"cookies": [], "origins": []},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert started.status_code == 202, started.get_data(as_text=True)
    scan_id = started.get_json()["scan_id"]
    payload = _wait_for_terminal_scan(client, scan_id, timeout_seconds=60.0)
    assert payload["status"] == "done", payload
    assert {"browser", "openapi", "graphql", "authorization_matrix"}.issubset(payload["artifacts"])
    assert payload["artifacts"]["browser"]["pages_visited"]
    assert payload["artifacts"]["openapi"]["operations"]
    assert payload["artifacts"]["graphql"]["introspection_enabled"] is True

    exported = client.get(f"/scan/{scan_id}/export-artifacts")
    assert exported.status_code == 200
    exported_text = exported.get_data(as_text=True)
    assert '"secrets_omitted": true' in exported_text
    assert low_secret not in exported_text and high_secret not in exported_text

    har = client.get(f"/scan/{scan_id}/export-har")
    assert har.status_code == 200
    har_payload = __import__("json").loads(har.data)
    assert har_payload["log"]["version"] == "1.2"
    assert har_payload["log"]["entries"]
    assert low_secret not in har.get_data(as_text=True) and high_secret not in har.get_data(as_text=True)

    for path in tmp_path.iterdir():
        if path.is_file():
            raw = path.read_bytes()
            assert low_secret.encode() not in raw and high_secret.encode() not in raw


def test_scan_can_be_enqueued_to_encrypted_redis_backend(tmp_path, monkeypatch, lab_server):
    import fakeredis
    from cryptography.fernet import Fernet
    from services.distributed_queue import DistributedQueue

    app_module = _load_app(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    client, csrf, _ = _register_and_login(app_module, "redis-queue@example.com")
    fake_client = fakeredis.FakeRedis(decode_responses=False)
    queue = DistributedQueue(client=fake_client, cipher=Fernet(Fernet.generate_key()))
    monkeypatch.setattr(app_module, "redis_backend_enabled", lambda: True)
    monkeypatch.setattr(app_module, "get_queue", lambda: queue)

    secret = "Bearer redis-secret-never-plaintext"
    response = client.post(
        "/scan-live",
        json={
            "url": lab_server + "/safe/headers",
            "vulns": ["clickjacking_scanner"],
            "authorized": True,
            "http_headers": {"Authorization": secret},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 202, response.get_data(as_text=True)
    raw = fake_client.lindex(queue.queue_key, 0)
    assert raw and secret.encode() not in raw
    job = queue.dequeue(timeout=1)
    assert job["runtime"]["default_headers"]["Authorization"] == secret
    scan_id = response.get_json()["scan_id"]
    status = client.get(f"/scan-status/{scan_id}").get_json()["scan"]
    assert status["status"] == "queued"
    assert secret not in str(status)
