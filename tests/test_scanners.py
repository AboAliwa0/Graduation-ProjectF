import json

import pytest

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
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


def test_html_injection_positive_and_non_executable_contexts(lab_server):
    assert_confirmed(html_injection.scan(lab_server + "/vuln/html", param="q"))
    assert_not_vulnerable(html_injection.scan(lab_server + "/safe/html", param="q"))
    assert_not_vulnerable(html_injection.scan(lab_server + "/safe/textarea", param="q"))


def test_xss_positive_and_non_executable_contexts(lab_server):
    assert_confirmed(xss.scan(lab_server + "/vuln/html", param="q"))
    assert_not_vulnerable(xss.scan(lab_server + "/safe/html", param="q"))
    assert_not_vulnerable(xss.scan(lab_server + "/safe/textarea", param="q"))


def test_sql_injection_and_dynamic_safe_page(lab_server):
    assert_confirmed(sql_injection.scan(lab_server + "/vuln/sqli", param="id"))
    assert_not_vulnerable(sql_injection.scan(lab_server + "/safe/dynamic", param="id"))


def test_path_traversal_canary_positive_and_negative(lab_server):
    kwargs = {"param": "file", "canary_path": "../private/cyberscan-canary.txt", "expected_marker": "CYBERSCAN_CANARY"}
    assert_confirmed(path_traversal.scan(lab_server + "/vuln/traversal", **kwargs))
    assert_not_vulnerable(path_traversal.scan(lab_server + "/safe/traversal", **kwargs))


def test_file_upload_positive_and_negative(lab_server):
    assert_confirmed(file_upload.scan(lab_server, upload_url=lab_server + "/vuln/upload", file_field="file", public_url_template=lab_server + "/public/{filename}"))
    assert_not_vulnerable(file_upload.scan(lab_server, upload_url=lab_server + "/safe/upload", file_field="file", public_url_template=lab_server + "/safe-public/{filename}"))


def test_idor_positive_and_negative(lab_server):
    kwargs = {"param": "id", "authorized_id": "1001", "test_id": "1002", "private_marker": "private_marker"}
    assert_confirmed(idor.scan(lab_server + "/vuln/idor", **kwargs))
    assert_not_vulnerable(idor.scan(lab_server + "/safe/idor", **kwargs))


def test_weak_password_positive_and_negative(lab_server):
    common = {"username_field": "username", "password_field": "password", "test_username": "test-user", "test_password": "Password1", "success_marker": "Welcome"}
    assert_confirmed(weak_password_scanner.scan(lab_server, login_url=lab_server + "/vuln/login", **common))
    assert_not_vulnerable(weak_password_scanner.scan(lab_server, login_url=lab_server + "/safe/login", **common))


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
    assert_confirmed(blind_xss.scan(lab_server + "/vuln/blind-xss", param="message", callback_base_url=lab_server))
