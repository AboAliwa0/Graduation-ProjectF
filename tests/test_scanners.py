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


def test_cors_positive_and_negative(lab_server):
    assert_confirmed(cors_scanner.scan(lab_server + "/vuln/cors"))
    assert_not_vulnerable(cors_scanner.scan(lab_server + "/safe/cors"))


def test_csrf_indicator_and_negative(lab_server):
    result = csrf_scan.scan(lab_server + "/vuln/csrf")
    assert result["vulnerable"] is True and result["status"] == "potential", result
    assert_not_vulnerable(csrf_scan.scan(lab_server + "/safe/csrf"))


def test_directory_listing_positive_and_negative(lab_server):
    assert_confirmed(dir_scan.scan(lab_server + "/lab/", paths="uploads/"))
    assert_not_vulnerable(dir_scan.scan(lab_server + "/lab-safe/", paths="uploads/"))


def test_information_disclosure_positive_and_header_only_negative(lab_server):
    assert_confirmed(info_scan.scan(lab_server + "/vuln/info"))
    assert_not_vulnerable(info_scan.scan(lab_server + "/safe/headers"))


def test_graphql_indicator_and_negative(lab_server):
    result = graphql_scanner.scan(lab_server, endpoint=lab_server + "/vuln/graphql")
    assert result["vulnerable"] is True and result["status"] == "potential", result
    assert_not_vulnerable(graphql_scanner.scan(lab_server, endpoint=lab_server + "/safe/graphql"))


def test_open_redirect_positive_and_negative(lab_server):
    assert_confirmed(open_redirect_scanner.scan(lab_server + "/vuln/redirect", param="next"))
    assert_not_vulnerable(open_redirect_scanner.scan(lab_server + "/safe/redirect", param="next"))


def test_host_header_body_reflection_is_potential_and_safe_is_negative(lab_server):
    result = host_header_scanner.scan(lab_server + "/vuln/host")
    assert result["vulnerable"] is True and result["status"] == "potential", result
    assert_not_vulnerable(host_header_scanner.scan(lab_server + "/safe/host"))


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


def test_generic_rate_limit_observation(lab_server):
    vulnerable = rate_limit.scan(lab_server + "/vuln/rate")
    assert vulnerable["vulnerable"] is True and vulnerable["status"] == "potential", vulnerable
    assert_not_vulnerable(rate_limit.scan(lab_server + "/safe/rate"))


def test_stored_xss_positive_and_negative(lab_server):
    assert_confirmed(stored_xss_scanner.scan(lab_server, submit_url=lab_server + "/vuln/stored", view_url=lab_server + "/vuln/stored-view", param_name="comment"))
    assert_not_vulnerable(stored_xss_scanner.scan(lab_server, submit_url=lab_server + "/safe/stored", view_url=lab_server + "/safe/stored-view", param_name="comment"))


def test_ssrf_requires_real_callback(lab_server):
    assert_confirmed(ssrf_scanner.scan(lab_server + "/vuln/ssrf", param="url", callback_base_url=lab_server))


def test_blind_xss_requires_real_callback(lab_server):
    assert_confirmed(blind_xss.scan(lab_server + "/vuln/blind-xss", param="message", callback_base_url=lab_server))
