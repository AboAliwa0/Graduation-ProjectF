import json

import pytest

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, ScanRuntime, activate_runtime
from vulnerabilities.common import make_result, safe_request
from vulnerabilities import (
    auth_scanner,
    blind_xss,
    clickjacking_scanner,
    cors_scanner,
    csrf_scan,
    dir_scan,
    file_upload,
    graphql_scanner,
    host_header_scanner,
    html_injection,
    idor,
    info_scan,
    open_redirect_scanner,
    path_traversal,
    rate_limit,
    sql_injection,
    ssrf_scanner,
    stored_xss_scanner,
    weak_password_scanner,
    xss,
)


def assert_confirmed(result):
    assert result["vulnerable"] is True, result
    assert result["status"] == "confirmed", result
    assert result["confidence"] in {"Medium", "High"}, result
    assert result["evidence"], result


def assert_not_vulnerable(result):
    assert result["vulnerable"] is False, result
    assert result["status"] in {"not_vulnerable", "inconclusive"}, result


def test_clickjacking_positive_and_negative(lab_server):
    assert_confirmed(clickjacking_scanner.scan(lab_server + "/vuln/clickjacking"))
    assert_not_vulnerable(clickjacking_scanner.scan(lab_server + "/safe/headers"))


def test_clickjacking_parses_frame_ancestors_and_skips_non_html(lab_server):
    protected = clickjacking_scanner.scan(lab_server + "/safe/csp-self")
    assert_not_vulnerable(protected)
    assert protected["evidence"]["frame_ancestors"] == ["'self'"]

    wildcard = clickjacking_scanner.scan(lab_server + "/vuln/csp-wildcard")
    assert_confirmed(wildcard)
    assert wildcard["evidence"]["frame_ancestors"] == ["*"]

    api_result = clickjacking_scanner.scan(lab_server + "/api/json")
    assert api_result["status"] == "inconclusive"
    assert api_result["evidence"]["content_type"].startswith("application/json")


def test_cors_positive_and_negative(lab_server):
    confirmed = cors_scanner.scan(lab_server + "/vuln/cors")
    assert_confirmed(confirmed)
    assert confirmed["requests_made"] == 3
    assert all("vary" in item and "vary_origin" in item for item in confirmed["evidence"]["observations"])
    assert_not_vulnerable(cors_scanner.scan(lab_server + "/safe/cors"))


def test_cors_conservative_classification(lab_server):
    reflected = cors_scanner.scan(lab_server + "/potential/cors")
    assert reflected["status"] == "potential"

    wildcard = cors_scanner.scan(lab_server + "/info/cors-wildcard")
    assert wildcard["status"] == "not_vulnerable"
    assert "observations were recorded" in wildcard["result"]

    failed_preflight = cors_scanner.scan(lab_server + "/safe/cors-failed-preflight")
    assert failed_preflight["status"] == "not_vulnerable"
    preflight = failed_preflight["evidence"]["observations"][-1]
    assert preflight["status_code"] == 403
    assert preflight["classification"] == "informational"


def test_cors_transport_error_counts_attempt_and_runtime_stops_propagate(monkeypatch, lab_server):
    def transport_error(*args, **kwargs):
        raise OSError("transport failed")

    monkeypatch.setattr(cors_scanner, "safe_request", transport_error)
    result = cors_scanner.scan(lab_server)
    assert result["status"] == "error"
    assert result["requests_made"] == 1

    for exception in (ScanCancelled("cancelled"), RequestBudgetExceeded("budget")):
        def runtime_stop(*args, _exception=exception, **kwargs):
            raise _exception

        monkeypatch.setattr(cors_scanner, "safe_request", runtime_stop)
        with pytest.raises(type(exception)):
            cors_scanner.scan(lab_server)


def test_csrf_indicator_and_negative(lab_server):
    result = csrf_scan.scan(lab_server + "/vuln/csrf")
    assert result["vulnerable"] is True and result["status"] == "potential", result
    assert result["evidence"]["form_count"] == 1
    assert result["evidence"]["risky_form_count"] == 1
    assert result["evidence"]["methods"] == ["POST"]
    assert result["evidence"]["actions"]

    safe = csrf_scan.scan(lab_server + "/safe/csrf")
    assert_not_vulnerable(safe)
    assert safe["evidence"]["form_count"] == 2
    assert safe["evidence"]["risky_form_count"] == 1
    assert safe["evidence"]["detected_csrf_controls"]

    no_forms = csrf_scan.scan(lab_server + "/safe/headers")
    assert_not_vulnerable(no_forms)
    assert no_forms["evidence"]["form_count"] == 0

    non_html = csrf_scan.scan(lab_server + "/api/json")
    assert_not_vulnerable(non_html)
    assert non_html["evidence"]["content_type"].startswith("application/json")


def test_directory_listing_positive_and_negative(lab_server):
    confirmed = dir_scan.scan(lab_server + "/lab/", paths="uploads/")
    assert_confirmed(confirmed)
    listing = confirmed["evidence"]["listings"][0]
    assert listing["path"] == "uploads/"
    assert listing["status_code"] == 200
    assert listing["signature"]
    assert listing["link_count"] >= 2

    safe_404 = dir_scan.scan(lab_server + "/lab-safe/", paths="uploads/")
    assert_not_vulnerable(safe_404)
    assert safe_404["evidence"]["checked_paths"][0]["status_code"] == 404

    custom = dir_scan.scan(lab_server + "/lab-custom/", paths="uploads/")
    assert_not_vulnerable(custom)
    assert custom["evidence"]["checked_paths"][0]["signature"] == ""

    external = lab_server.replace("127.0.0.1", "localhost") + "/lab/uploads/"
    blocked = dir_scan.scan(lab_server + "/lab/", paths=external)
    assert blocked["status"] == "inconclusive"
    assert blocked["requests_made"] == 0
    assert blocked["evidence"]["final_decision"] == "no_safe_same_origin_paths"


def test_information_disclosure_positive_and_header_only_negative(lab_server):
    assert_confirmed(info_scan.scan(lab_server + "/vuln/info"))
    assert_not_vulnerable(info_scan.scan(lab_server + "/safe/headers"))


def test_graphql_indicator_and_negative(lab_server):
    result = graphql_scanner.scan(lab_server, endpoint=lab_server + "/vuln/graphql")
    assert result["vulnerable"] is True and result["status"] == "potential", result
    assert_not_vulnerable(graphql_scanner.scan(lab_server, endpoint=lab_server + "/safe/graphql"))


def test_open_redirect_positive_and_negative(lab_server):
    confirmed = open_redirect_scanner.scan(lab_server + "/vuln/redirect", param="next")
    assert_confirmed(confirmed)
    assert confirmed["evidence"]["parameter"] == "next"
    assert confirmed["evidence"]["payload"].startswith("https://redirect-")
    assert confirmed["evidence"]["final_decision"] == "external_redirect_confirmed"

    safe = open_redirect_scanner.scan(lab_server + "/safe/redirect", param="next")
    assert_not_vulnerable(safe)
    assert safe["evidence"]["final_decision"] == "no_external_3xx_redirect"

    missing = open_redirect_scanner.scan(lab_server + "/vuln/redirect")
    assert missing["status"] == "inconclusive"
    assert missing["requests_made"] == 0
    assert missing["evidence"]["reason"] == "missing_required_parameter"


def test_host_header_body_reflection_is_potential_and_safe_is_negative(lab_server):
    result = host_header_scanner.scan(lab_server + "/vuln/host")
    assert result["vulnerable"] is True and result["status"] == "potential", result
    assert result["evidence"]["tested_host"].endswith(".invalid")
    assert "body" in result["evidence"]["observations"][0]["reflection_context"]
    assert_not_vulnerable(host_header_scanner.scan(lab_server + "/safe/host"))

    redirect_result = host_header_scanner.scan(lab_server + "/vuln/host-redirect")
    assert_confirmed(redirect_result)
    assert any("location" in item["reflection_context"] for item in redirect_result["evidence"]["observations"])
    assert redirect_result["evidence"]["final_decision"] == "confirmed_external_3xx_redirect"

    location_without_redirect = host_header_scanner.scan(lab_server + "/vuln/host-location-200")
    assert location_without_redirect["status"] == "potential"
    assert location_without_redirect["vulnerable"] is True
    assert location_without_redirect["evidence"]["final_decision"] == "potential_host_reflection"


def test_redirect_policy_preserves_same_origin_auth_and_blocks_cross_origin(lab_server):
    same_runtime = ScanRuntime(
        scan_id=9001,
        user_id=1,
        request_budget=5,
        default_headers={"Authorization": "Bearer same-origin-secret"},
        cookies={"session": "same-origin-cookie"},
        allow_private=True,
    )
    with activate_runtime(same_runtime):
        same = safe_request("GET", lab_server + "/redirect/same-origin", allow_redirects=True)
    assert same.status_code == 200
    assert same.json()["authorization"] == "Bearer same-origin-secret"
    assert "session=same-origin-cookie" in same.json()["cookie"]
    assert same_runtime.request_count == 2

    cross_runtime = ScanRuntime(
        scan_id=9002,
        user_id=1,
        request_budget=5,
        default_headers={"Authorization": "Bearer never-cross-origin"},
        cookies={"session": "never-cross-origin-cookie"},
        allow_private=True,
    )
    with activate_runtime(cross_runtime):
        cross = safe_request("GET", lab_server + "/redirect/cross-origin", allow_redirects=True)
    assert cross.status_code == 302
    assert cross_runtime.request_count == 1


def test_sensitive_query_values_are_redacted_in_result_urls(lab_server):
    raw_secret = "do-not-store-this-value"
    result = make_result(
        True,
        "Safe URL redaction test",
        evidence={
            "endpoint": f"{lab_server}/account?access_token={raw_secret}&view=summary",
            "actions": [f"{lab_server}/login?code={raw_secret}&next=dashboard"],
            "location": f"/callback?session={raw_secret}&mode=test",
        },
        endpoint=f"{lab_server}/scan?api_key={raw_secret}&page=1",
    )
    serialized = json.dumps(result)
    assert raw_secret not in serialized
    assert "/account?" in result["evidence"]["endpoint"]
    assert "view=summary" in result["evidence"]["endpoint"]
    assert "page=1" in result["endpoint"]

    redirect_result = open_redirect_scanner.scan(lab_server + "/safe/redirect-sensitive", param="next")
    assert raw_secret not in json.dumps(redirect_result)
    assert "fixture-secret" not in json.dumps(redirect_result)


def test_html_injection_positive_and_non_executable_contexts(lab_server):
    confirmed = html_injection.scan(lab_server + "/vuln/html", param="q")
    assert_confirmed(confirmed)
    assert confirmed["evidence"]["reflected_raw"] is True
    assert confirmed["evidence"]["custom_element_parsed"] is True
    assert confirmed["evidence"]["final_decision"] == "parsed_custom_element_confirmed"

    encoded = html_injection.scan(lab_server + "/safe/html", param="q")
    assert_not_vulnerable(encoded)
    assert encoded["evidence"]["reflected_raw"] is False
    assert encoded["evidence"]["reflected_decoded"] is True
    assert encoded["evidence"]["custom_element_parsed"] is False

    textarea = html_injection.scan(lab_server + "/safe/textarea", param="q")
    assert_not_vulnerable(textarea)
    assert textarea["evidence"]["custom_element_parsed"] is False


def test_xss_positive_and_non_executable_contexts(lab_server):
    confirmed = xss.scan(lab_server + "/vuln/html", param="q")
    assert_confirmed(confirmed)
    assert confirmed["evidence"]["final_decision"] == "executable_context_confirmed"
    assert confirmed["evidence"]["detection"]["executable_context_confirmed"] is True

    encoded = xss.scan(lab_server + "/safe/html", param="q")
    assert_not_vulnerable(encoded)
    assert encoded["evidence"]["final_decision"] in {"reflected_non_executable", "no_reflection_detected"}
    assert any("final_decision" in item for item in encoded["evidence"]["attempts"])

    textarea = xss.scan(lab_server + "/safe/textarea", param="q")
    assert_not_vulnerable(textarea)
    assert all(not item["executable_context_confirmed"] for item in textarea["evidence"]["attempts"])

    title = xss.scan(lab_server + "/safe/title", param="q")
    assert_not_vulnerable(title)
    assert all(not item["executable_context_confirmed"] for item in title["evidence"]["attempts"])


def test_sql_injection_and_dynamic_safe_page(lab_server):
    confirmed = sql_injection.scan(lab_server + "/vuln/sqli", param="id")
    assert_confirmed(confirmed)
    assert confirmed["evidence"]["classification"] == "confirmed"
    assert confirmed["evidence"]["baseline_summary"]["status_codes"]
    assert confirmed["evidence"]["database_errors"][0]["final_decision"] == "confirmed_database_error"

    safe_dynamic = sql_injection.scan(lab_server + "/safe/dynamic", param="id")
    assert_not_vulnerable(safe_dynamic)
    assert "final_decision" in safe_dynamic["evidence"]


def test_path_traversal_canary_positive_and_negative(lab_server):
    kwargs = {"param": "file", "canary_path": "../private/cyberscan-canary.txt", "expected_marker": "CYBERSCAN_CANARY"}
    confirmed = path_traversal.scan(lab_server + "/vuln/traversal", **kwargs)
    assert_confirmed(confirmed)
    assert confirmed["evidence"]["payload_family"] == "lab_canary"
    assert confirmed["evidence"]["marker_matched"] is True
    assert confirmed["evidence"]["checked_probes"]

    safe = path_traversal.scan(lab_server + "/safe/traversal", **kwargs)
    assert_not_vulnerable(safe)
    assert safe["evidence"]["final_decision"] == "no_marker_or_signature_match"
    assert safe["evidence"]["checked_probes"][0]["status_code"] == 404


def test_phase2_missing_required_inputs_are_inconclusive(lab_server):
    for result in (
        sql_injection.scan(lab_server + "/vuln/sqli"),
        html_injection.scan(lab_server + "/vuln/html"),
        path_traversal.scan(lab_server + "/vuln/traversal"),
    ):
        assert result["status"] == "inconclusive"
        assert result["requests_made"] == 0
        assert result["evidence"]["reason"] == "missing_required_parameter"


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (xss, {"param": "q"}),
        (sql_injection, {"param": "id"}),
        (html_injection, {"param": "q"}),
        (path_traversal, {"param": "file", "canary_path": "../private/cyberscan-canary.txt", "expected_marker": "CYBERSCAN_CANARY"}),
    ],
)
def test_phase2_scanners_transport_error_counts_attempt(monkeypatch, lab_server, module, kwargs):
    def fail_request(*args, **request_kwargs):
        raise OSError("transport failed")

    monkeypatch.setattr(module, "safe_request", fail_request)
    result = module.scan(lab_server, **kwargs)
    assert result["status"] == "error"
    assert result["requests_made"] == 1


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (xss, {"param": "q"}),
        (sql_injection, {"param": "id"}),
        (html_injection, {"param": "q"}),
        (path_traversal, {"param": "file", "canary_path": "../private/cyberscan-canary.txt", "expected_marker": "CYBERSCAN_CANARY"}),
    ],
)
@pytest.mark.parametrize("exception", [ScanCancelled("cancelled"), RequestBudgetExceeded("budget")])
def test_phase2_scanners_propagate_runtime_stop_exceptions(monkeypatch, lab_server, module, kwargs, exception):
    def stop_request(*args, **request_kwargs):
        raise exception

    monkeypatch.setattr(module, "safe_request", stop_request)
    with pytest.raises(type(exception)):
        module.scan(lab_server, **kwargs)


def test_file_upload_positive_and_negative(lab_server):
    assert_confirmed(file_upload.scan(lab_server, upload_url=lab_server + "/vuln/upload", file_field="file", public_url_template=lab_server + "/public/{filename}"))
    assert_not_vulnerable(file_upload.scan(lab_server, upload_url=lab_server + "/safe/upload", file_field="file", public_url_template=lab_server + "/safe-public/{filename}"))


def test_idor_positive_and_negative(lab_server):
    kwargs = {
        "param": "id",
        "authorized_id": "1001",
        "test_id": "1002",
        "private_marker": "private_marker",
        "auth_header_name": "X-Test-Authorization",
        "auth_header_value": "fixture-secret-token",
    }
    assert_confirmed(idor.scan(lab_server + "/vuln/idor", **kwargs))
    assert_not_vulnerable(idor.scan(lab_server + "/safe/idor", **kwargs))


def test_weak_password_positive_and_negative(lab_server):
    common = {"username_field": "username", "password_field": "password", "test_username": "test-user", "test_password": "Password1", "success_marker": "Welcome"}
    assert_confirmed(weak_password_scanner.scan(lab_server, login_url=lab_server + "/vuln/login", **common))
    assert_not_vulnerable(weak_password_scanner.scan(lab_server, login_url=lab_server + "/safe/login", **common))


def test_phase4a_missing_inputs_and_identical_ids_are_inconclusive(monkeypatch, lab_server):
    modules_and_calls = [
        (idor, {"url": lab_server, "param": "id", "authorized_id": "1001", "test_id": "1002"}),
        (weak_password_scanner, {"url": lab_server, "login_url": lab_server + "/vuln/login"}),
        (file_upload, {"url": lab_server, "upload_url": lab_server + "/vuln/upload"}),
        (stored_xss_scanner, {"url": lab_server, "submit_url": lab_server + "/vuln/stored"}),
    ]
    for module, kwargs in modules_and_calls:
        monkeypatch.setattr(module, "safe_request", lambda *args, **request_kwargs: pytest.fail("No request expected"))
        result = module.scan(**kwargs)
        assert result["status"] == "inconclusive", result
        assert result["requests_made"] == 0

    identical = idor.scan(
        lab_server,
        param="id",
        authorized_id="1001",
        test_id="1001",
        auth_header_name="Authorization",
        auth_header_value="Bearer fixture-secret",
    )
    assert identical["status"] == "inconclusive"
    assert identical["requests_made"] == 0
    assert "1001" not in json.dumps(identical["evidence"])


def test_idor_requires_auth_keeps_parity_potential_and_redacts_evidence(lab_server):
    missing_auth = idor.scan(lab_server + "/vuln/idor", param="id", authorized_id="1001", test_id="1002", private_marker="private_marker")
    assert missing_auth["status"] == "inconclusive"
    assert missing_auth["requests_made"] == 0

    secret = "Bearer instructor-fixture-secret"
    potential = idor.scan(
        lab_server + "/potential/idor",
        param="id",
        authorized_id="1001",
        test_id="1002",
        auth_header_name="Authorization",
        auth_header_value=secret,
    )
    assert potential["status"] == "potential" and potential["vulnerable"] is True, potential
    assert potential["evidence"]["final_decision"] == "potential_response_parity"
    serialized = json.dumps(potential["evidence"])
    assert "1001" not in serialized and "1002" not in serialized
    assert secret not in serialized and "Authorization" not in serialized


def test_weak_credential_requires_reliable_success_and_redacts_evidence(lab_server):
    common = {
        "test_username": "instructor-test-user",
        "test_password": "fixture-weak-password",
        "success_marker": "Welcome",
    }
    rejected = weak_password_scanner.scan(lab_server, login_url=lab_server + "/login/marker-401", **common)
    assert_not_vulnerable(rejected)
    assert rejected["evidence"]["final_decision"] == "credential_rejected"

    redirected = weak_password_scanner.scan(
        lab_server,
        login_url=lab_server + "/login/redirect",
        test_username=common["test_username"],
        test_password=common["test_password"],
        success_redirect_contains="/dashboard",
    )
    assert_confirmed(redirected)
    serialized = json.dumps(redirected["evidence"])
    assert common["test_username"] not in serialized
    assert common["test_password"] not in serialized
    assert "fixture-secret" not in serialized

    missing_criterion = weak_password_scanner.scan(
        lab_server,
        login_url=lab_server + "/vuln/login",
        test_username=common["test_username"],
        test_password=common["test_password"],
    )
    assert missing_criterion["status"] == "inconclusive"
    assert missing_criterion["requests_made"] == 0


def test_file_upload_requires_safe_retrieval_and_redacts_marker(lab_server):
    no_retrieval = file_upload.scan(lab_server, upload_url=lab_server + "/safe/upload", file_field="file")
    assert no_retrieval["status"] == "inconclusive"
    assert no_retrieval["requests_made"] == 1
    assert no_retrieval["evidence"]["final_decision"] == "no_safe_retrieval_url"

    cross_origin = file_upload.scan(lab_server, upload_url=lab_server + "/upload/cross-origin", file_field="file")
    assert cross_origin["status"] == "inconclusive"
    assert cross_origin["requests_made"] == 1
    assert cross_origin["evidence"]["discovered_url_rejected"] is True

    confirmed = file_upload.scan(lab_server, upload_url=lab_server + "/vuln/upload", file_field="file")
    assert_confirmed(confirmed)
    assert confirmed["evidence"]["marker_retrieved"] is True
    assert "filename" not in confirmed["evidence"] and "public_url" not in confirmed["evidence"]
    assert "upload-" not in json.dumps(confirmed["evidence"])


def test_stored_xss_failed_steps_are_inconclusive_and_marker_is_redacted(lab_server):
    failed_submit = stored_xss_scanner.scan(
        lab_server,
        submit_url=lab_server + "/stored/fail-submit",
        view_url=lab_server + "/vuln/stored-view",
        param_name="comment",
    )
    assert failed_submit["status"] == "inconclusive"
    assert failed_submit["requests_made"] == 1
    assert failed_submit["evidence"]["final_decision"] == "submission_failed"

    failed_view = stored_xss_scanner.scan(
        lab_server,
        submit_url=lab_server + "/vuln/stored",
        view_url=lab_server + "/stored/fail-view",
        param_name="comment",
    )
    assert failed_view["status"] == "inconclusive"
    assert failed_view["requests_made"] == 2
    assert failed_view["evidence"]["final_decision"] == "view_not_successful_html"

    escaped = stored_xss_scanner.scan(
        lab_server,
        submit_url=lab_server + "/safe/stored",
        view_url=lab_server + "/safe/stored-view",
        param_name="comment",
    )
    assert_not_vulnerable(escaped)
    assert "token" not in escaped["evidence"]
    assert "storedxss-" not in json.dumps(escaped["evidence"])


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (idor, {"param": "id", "authorized_id": "1001", "test_id": "1002", "private_marker": "private_marker", "auth_header_name": "Authorization", "auth_header_value": "Bearer fixture"}),
        (weak_password_scanner, {"login_url": "https://target.example/login", "test_username": "test-user", "test_password": "Password1", "success_marker": "Welcome"}),
        (file_upload, {"upload_url": "https://target.example/upload", "file_field": "file", "public_url_template": "https://target.example/public/{filename}"}),
        (stored_xss_scanner, {"submit_url": "https://target.example/submit", "view_url": "https://target.example/view", "param_name": "comment"}),
    ],
)
def test_phase4a_transport_errors_count_attempt(monkeypatch, lab_server, module, kwargs):
    monkeypatch.setattr(module, "safe_request", lambda *args, **request_kwargs: (_ for _ in ()).throw(OSError("transport failed")))
    result = module.scan(lab_server, **kwargs)
    assert result["status"] == "error", result
    assert result["requests_made"] == 1


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (idor, {"param": "id", "authorized_id": "1001", "test_id": "1002", "private_marker": "private_marker", "auth_header_name": "Authorization", "auth_header_value": "Bearer fixture"}),
        (weak_password_scanner, {"login_url": "https://target.example/login", "test_username": "test-user", "test_password": "Password1", "success_marker": "Welcome"}),
        (file_upload, {"upload_url": "https://target.example/upload", "file_field": "file", "public_url_template": "https://target.example/public/{filename}"}),
        (stored_xss_scanner, {"submit_url": "https://target.example/submit", "view_url": "https://target.example/view", "param_name": "comment"}),
    ],
)
@pytest.mark.parametrize("exception", [ScanCancelled("cancelled"), RequestBudgetExceeded("budget")])
def test_phase4a_runtime_stop_exceptions_propagate(monkeypatch, lab_server, module, kwargs, exception):
    monkeypatch.setattr(module, "safe_request", lambda *args, **request_kwargs: (_ for _ in ()).throw(exception))
    with pytest.raises(type(exception)):
        module.scan(lab_server, **kwargs)


def test_login_abuse_protection(lab_server):
    vulnerable = auth_scanner.scan(lab_server, login_url=lab_server + "/vuln/auth", test_username="security-test", failure_marker="Invalid credentials")
    assert vulnerable["vulnerable"] is True and vulnerable["status"] == "potential", vulnerable
    assert_not_vulnerable(auth_scanner.scan(lab_server, login_url=lab_server + "/safe/auth", test_username="security-test", failure_marker="Invalid credentials"))


def test_login_abuse_missing_inputs_are_inconclusive_without_requests(monkeypatch, lab_server):
    monkeypatch.setattr(auth_scanner, "safe_request", lambda *args, **kwargs: pytest.fail("No request expected"))
    missing_url = auth_scanner.scan(lab_server, test_username="security-test", failure_marker="Invalid credentials")
    missing_user = auth_scanner.scan(lab_server, login_url=lab_server + "/auth/no-protection", failure_marker="Invalid credentials")
    missing_marker = auth_scanner.scan(lab_server, login_url=lab_server + "/auth/no-protection", test_username="security-test")
    for result in (missing_url, missing_user, missing_marker):
        assert result["status"] == "inconclusive"
        assert result["requests_made"] == 0
        assert result["evidence"]["attempt_count"] == 0


def test_login_abuse_five_attempt_limit_potential_and_secret_free_evidence(lab_server):
    username = "dedicated-instructor-account"
    result = auth_scanner.scan(
        lab_server,
        login_url=lab_server + "/auth/no-protection",
        test_username=username,
        failure_marker="Invalid credentials",
    )
    assert result["status"] == "potential" and result["confidence"] == "Low", result
    assert result["requests_made"] == auth_scanner.MAX_ATTEMPTS == 5
    assert result["evidence"]["attempt_count"] == 5
    serialized = json.dumps(result["evidence"])
    assert username not in serialized
    assert "CyberScan-Wrong" not in serialized


def test_login_abuse_stops_early_on_429_and_retry_after(lab_server):
    common = {"test_username": "security-test", "failure_marker": "Invalid credentials"}
    limited = auth_scanner.scan(lab_server, login_url=lab_server + "/auth/http-429", **common)
    assert_not_vulnerable(limited)
    assert limited["evidence"]["throttling_observed"] is True
    assert limited["evidence"]["attempt_count"] == 3

    retried = auth_scanner.scan(lab_server, login_url=lab_server + "/auth/retry-after", **common)
    assert_not_vulnerable(retried)
    assert retried["evidence"]["retry_after_observed"] is True
    assert retried["evidence"]["attempt_count"] == 2


@pytest.mark.parametrize(
    ("path", "marker_name", "marker_value", "evidence_key"),
    [
        ("/auth/captcha", "captcha_marker", "CAPTCHA required", "captcha_observed"),
        ("/auth/lockout", "lockout_marker", "Account locked", "lockout_observed"),
        ("/auth/rate-marker", "rate_limit_marker", "Slow down", "rate_limit_marker_observed"),
    ],
)
def test_login_abuse_recognizes_protection_markers(lab_server, path, marker_name, marker_value, evidence_key):
    result = auth_scanner.scan(
        lab_server,
        login_url=lab_server + path,
        test_username="security-test",
        failure_marker="Invalid credentials",
        **{marker_name: marker_value},
    )
    assert_not_vulnerable(result)
    assert result["severity"] == "Info"
    assert result["evidence"][evidence_key] is True
    assert result["evidence"]["attempt_count"] == 1


def test_login_abuse_invalid_failure_marker_is_inconclusive(lab_server):
    result = auth_scanner.scan(
        lab_server,
        login_url=lab_server + "/auth/unreliable",
        test_username="security-test",
        failure_marker="Invalid credentials",
    )
    assert result["status"] == "inconclusive" and result["vulnerable"] is False
    assert result["evidence"]["failure_evidence_consistent"] is False


@pytest.mark.parametrize("exception", [ScanCancelled("cancelled"), RequestBudgetExceeded("budget")])
def test_login_abuse_propagates_runtime_stop_exceptions(monkeypatch, lab_server, exception):
    def stop_request(*args, **kwargs):
        raise exception

    monkeypatch.setattr(auth_scanner, "safe_request", stop_request)
    with pytest.raises(type(exception)):
        auth_scanner.scan(
            lab_server,
            login_url=lab_server + "/auth/no-protection",
            test_username="security-test",
            failure_marker="Invalid credentials",
        )


def test_login_abuse_transport_error_counts_attempt(monkeypatch, lab_server):
    def fail_request(*args, **kwargs):
        raise OSError("transport failed")

    monkeypatch.setattr(auth_scanner, "safe_request", fail_request)
    result = auth_scanner.scan(
        lab_server,
        login_url=lab_server + "/auth/no-protection",
        test_username="security-test",
        failure_marker="Invalid credentials",
    )
    assert result["status"] == "error"
    assert result["requests_made"] == 1


def test_generic_rate_limit_observation(lab_server):
    vulnerable = rate_limit.scan(lab_server + "/vuln/rate")
    assert vulnerable["vulnerable"] is True and vulnerable["status"] == "potential", vulnerable
    assert vulnerable["confidence"] == "Low"
    assert vulnerable["evidence"]["attempt_count"] == 5
    assert vulnerable["evidence"]["conclusion"] == "no_explicit_throttling_observed"

    limited = rate_limit.scan(lab_server + "/safe/rate")
    assert_not_vulnerable(limited)
    assert limited["evidence"]["retry_after"]

    delayed = rate_limit.scan(lab_server + "/safe/rate-delay")
    assert_not_vulnerable(delayed)
    assert delayed["evidence"]["progressive_delay_observed"] is True


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (host_header_scanner, {}),
        (csrf_scan, {}),
        (dir_scan, {"paths": "uploads/"}),
        (open_redirect_scanner, {"param": "next"}),
        (rate_limit, {}),
    ],
)
def test_phase1_scanners_transport_error_counts_attempt(monkeypatch, lab_server, module, kwargs):
    def fail_request(*args, **request_kwargs):
        raise OSError("transport failed")

    monkeypatch.setattr(module, "safe_request", fail_request)
    result = module.scan(lab_server, **kwargs)
    assert result["status"] == "error"
    assert result["requests_made"] == 1


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (host_header_scanner, {}),
        (csrf_scan, {}),
        (dir_scan, {"paths": "uploads/"}),
        (open_redirect_scanner, {"param": "next"}),
        (rate_limit, {}),
    ],
)
@pytest.mark.parametrize("exception", [ScanCancelled("cancelled"), RequestBudgetExceeded("budget")])
def test_phase1_scanners_propagate_runtime_stop_exceptions(monkeypatch, lab_server, module, kwargs, exception):
    def stop_request(*args, **request_kwargs):
        raise exception

    monkeypatch.setattr(module, "safe_request", stop_request)
    with pytest.raises(type(exception)):
        module.scan(lab_server, **kwargs)


def test_stored_xss_positive_and_negative(lab_server):
    assert_confirmed(stored_xss_scanner.scan(lab_server, submit_url=lab_server + "/vuln/stored", view_url=lab_server + "/vuln/stored-view", param_name="comment"))
    assert_not_vulnerable(stored_xss_scanner.scan(lab_server, submit_url=lab_server + "/safe/stored", view_url=lab_server + "/safe/stored-view", param_name="comment"))


def test_ssrf_requires_real_callback(lab_server):
    assert_confirmed(ssrf_scanner.scan(lab_server + "/vuln/ssrf", param="url", callback_base_url=lab_server))


def test_blind_xss_requires_real_callback(lab_server):
    fetched_only = blind_xss.scan(lab_server + "/vuln/blind-xss", param="message", callback_base_url=lab_server)
    assert fetched_only["status"] == "potential" and fetched_only["vulnerable"] is True, fetched_only
    assert fetched_only["evidence"]["script_fetch_observed"] is True
    assert fetched_only["evidence"]["execution_beacon_observed"] is False

    executed = blind_xss.scan(lab_server + "/vuln/blind-xss-execute", param="message", callback_base_url=lab_server)
    assert_confirmed(executed)
    assert executed["evidence"]["execution_beacon_observed"] is True


def test_phase4b_missing_callback_setup_is_inconclusive(monkeypatch, lab_server):
    monkeypatch.delenv("OAST_PUBLIC_BASE_URL", raising=False)
    for module, kwargs in (
        (ssrf_scanner, {"param": "url"}),
        (blind_xss, {"param": "message"}),
    ):
        monkeypatch.setattr(module, "safe_request", lambda *args, **request_kwargs: pytest.fail("No request expected"))
        result = module.scan(lab_server, **kwargs)
        assert result["status"] == "inconclusive", result
        assert result["requests_made"] == 0
        assert result["evidence"]["callback_configured"] is False


def test_phase4b_no_callback_observed_is_inconclusive(monkeypatch, lab_server):
    monkeypatch.setattr(ssrf_scanner, "wait_for_hit", lambda token, timeout: [])
    ssrf_result = ssrf_scanner.scan(lab_server + "/safe/ssrf", param="url", callback_base_url=lab_server)
    assert ssrf_result["status"] == "inconclusive"
    assert ssrf_result["evidence"]["callback_observed"] is False
    assert ssrf_result["evidence"]["hit_count"] == 0

    monkeypatch.setattr(blind_xss, "wait_for_hit", lambda token, timeout: [])
    blind_result = blind_xss.scan(lab_server + "/safe/blind-xss", param="message", callback_base_url=lab_server)
    assert blind_result["status"] == "inconclusive"
    assert blind_result["evidence"]["script_fetch_observed"] is False
    assert blind_result["evidence"]["execution_beacon_observed"] is False


def test_phase4b_private_callback_requires_explicit_local_lab_mode(monkeypatch, lab_server):
    monkeypatch.setenv("OAST_ALLOW_PRIVATE_CALLBACKS", "false")
    for module, kwargs in (
        (ssrf_scanner, {"param": "url"}),
        (blind_xss, {"param": "message"}),
    ):
        result = module.scan(lab_server, callback_base_url=lab_server, **kwargs)
        assert result["status"] == "inconclusive", result
        assert result["requests_made"] == 0
        assert result["evidence"]["final_decision"] == "invalid_or_blocked_callback"


def test_phase4b_callback_evidence_redacts_tokens_and_urls(monkeypatch, lab_server):
    ssrf_token = "ssrf-raw-secret-token"
    monkeypatch.setattr(ssrf_scanner, "unique_token", lambda prefix: ssrf_token)
    ssrf_result = ssrf_scanner.scan(lab_server + "/vuln/ssrf", param="url", callback_base_url=lab_server)
    assert_confirmed(ssrf_result)
    serialized_ssrf = json.dumps(ssrf_result)
    assert ssrf_token not in serialized_ssrf
    assert "/oast/" not in serialized_ssrf
    assert "callback_hits" not in ssrf_result["evidence"]

    tokens = iter(["blind-fetch-raw-secret", "blind-exec-raw-secret"])
    monkeypatch.setattr(blind_xss, "unique_token", lambda prefix: next(tokens))
    blind_result = blind_xss.scan(
        lab_server + "/vuln/blind-xss-execute",
        param="message",
        callback_base_url=lab_server,
    )
    assert_confirmed(blind_result)
    serialized_blind = json.dumps(blind_result)
    assert "blind-fetch-raw-secret" not in serialized_blind
    assert "blind-exec-raw-secret" not in serialized_blind
    assert "/oast/" not in serialized_blind
    assert "callback_hits" not in blind_result["evidence"]


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (ssrf_scanner, {"param": "url"}),
        (blind_xss, {"param": "message"}),
    ],
)
def test_phase4b_transport_errors_count_attempt(monkeypatch, lab_server, module, kwargs):
    def fail_request(*args, **request_kwargs):
        raise OSError("transport failed")

    monkeypatch.setattr(module, "safe_request", fail_request)
    result = module.scan(lab_server, callback_base_url=lab_server, **kwargs)
    assert result["status"] == "error", result
    assert result["requests_made"] == 1


@pytest.mark.parametrize(
    "module, kwargs",
    [
        (ssrf_scanner, {"param": "url"}),
        (blind_xss, {"param": "message"}),
    ],
)
@pytest.mark.parametrize("exception", [ScanCancelled("cancelled"), RequestBudgetExceeded("budget")])
def test_phase4b_runtime_stop_exceptions_propagate(monkeypatch, lab_server, module, kwargs, exception):
    def stop_request(*args, **request_kwargs):
        raise exception

    monkeypatch.setattr(module, "safe_request", stop_request)
    with pytest.raises(type(exception)):
        module.scan(lab_server, callback_base_url=lab_server, **kwargs)
