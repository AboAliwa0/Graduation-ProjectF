from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("ALLOW_PRIVATE_TARGETS", "true")
os.environ.setdefault("OAST_ALLOW_PRIVATE_CALLBACKS", "true")
os.environ.setdefault("SCANNER_TIMEOUT", "3")

from services.scan_runtime import ScanRuntime, activate_runtime
from tests.conftest import lab_server
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
from vulnerabilities import authorization_matrix_scanner, modern_spa_scanner, oidc_scanner, openapi_scanner


@contextmanager
def running_lab():
    fixture = lab_server.__wrapped__()
    base_url = next(fixture)
    try:
        yield base_url
    finally:
        fixture.close()


def run_case(index: int, name: str, target: str, scanner, *args, runtime_ephemeral=None, **kwargs) -> dict:
    runtime = ScanRuntime(
        scan_id=8000 + index,
        user_id=1,
        request_budget=160,
        allow_private=True,
        ephemeral=runtime_ephemeral or {},
    )
    with activate_runtime(runtime):
        result = scanner(*args, **kwargs)
    return {
        "scanner": name,
        "target": target,
        "status": result.get("status", "unknown"),
        "vulnerable": bool(result.get("vulnerable")),
        "severity": result.get("severity", ""),
        "confidence": result.get("confidence", ""),
        "requests_made": result.get("requests_made", runtime.request_count),
        "summary": str(result.get("result", ""))[:180],
    }


def main() -> int:
    with running_lab() as base:
        auth_profiles = {
            "auth_profiles": [
                {"name": "user", "expected_access": "user", "headers": {"Authorization": "Bearer low-role"}, "cookies": {}},
                {"name": "admin", "expected_access": "admin", "headers": {"Authorization": "Bearer high-role"}, "cookies": {}},
            ]
        }
        cases = [
            ("clickjacking", f"{base}/vuln/clickjacking", clickjacking_scanner.scan, (f"{base}/vuln/clickjacking",), {}),
            ("cors", f"{base}/vuln/cors", cors_scanner.scan, (f"{base}/vuln/cors",), {}),
            ("csrf", f"{base}/vuln/csrf", csrf_scan.scan, (f"{base}/vuln/csrf",), {}),
            ("directory_listing", f"{base}/lab/uploads/", dir_scan.scan, (f"{base}/lab/",), {"paths": "uploads/"}),
            ("info_disclosure", f"{base}/vuln/info", info_scan.scan, (f"{base}/vuln/info",), {}),
            ("graphql_introspection", f"{base}/vuln/graphql", graphql_scanner.scan, (base,), {"endpoint": f"{base}/vuln/graphql"}),
            ("open_redirect", f"{base}/vuln/redirect", open_redirect_scanner.scan, (f"{base}/vuln/redirect",), {"param": "next"}),
            ("host_header", f"{base}/vuln/host-redirect", host_header_scanner.scan, (f"{base}/vuln/host-redirect",), {}),
            ("html_injection", f"{base}/vuln/html", html_injection.scan, (f"{base}/vuln/html",), {"param": "q"}),
            ("xss", f"{base}/vuln/html", xss.scan, (f"{base}/vuln/html",), {"param": "q"}),
            ("sql_injection", f"{base}/vuln/sqli", sql_injection.scan, (f"{base}/vuln/sqli",), {"param": "id"}),
            (
                "path_traversal",
                f"{base}/vuln/traversal",
                path_traversal.scan,
                (f"{base}/vuln/traversal",),
                {"param": "file", "canary_path": "../private/cyberscan-canary.txt", "expected_marker": "CYBERSCAN_CANARY"},
            ),
            (
                "file_upload",
                f"{base}/vuln/upload",
                file_upload.scan,
                (base,),
                {"upload_url": f"{base}/vuln/upload", "file_field": "file", "public_url_template": f"{base}/public/{{filename}}"},
            ),
            (
                "idor",
                f"{base}/vuln/idor",
                idor.scan,
                (f"{base}/vuln/idor",),
                {
                    "param": "id",
                    "authorized_id": "1001",
                    "test_id": "1002",
                    "private_marker": "private_marker",
                    "auth_header_name": "X-Test-Authorization",
                    "auth_header_value": "fixture-secret-token",
                },
            ),
            (
                "weak_password",
                f"{base}/vuln/login",
                weak_password_scanner.scan,
                (base,),
                {
                    "login_url": f"{base}/vuln/login",
                    "username_field": "username",
                    "password_field": "password",
                    "test_username": "test-user",
                    "test_password": "Password1",
                    "success_marker": "Welcome",
                },
            ),
            (
                "auth_abuse",
                f"{base}/vuln/auth",
                auth_scanner.scan,
                (base,),
                {"login_url": f"{base}/vuln/auth", "test_username": "security-test", "failure_marker": "Invalid credentials"},
            ),
            ("rate_limit", f"{base}/vuln/rate", rate_limit.scan, (f"{base}/vuln/rate",), {}),
            (
                "stored_xss",
                f"{base}/vuln/stored",
                stored_xss_scanner.scan,
                (base,),
                {"submit_url": f"{base}/vuln/stored", "view_url": f"{base}/vuln/stored-view", "param_name": "comment"},
            ),
            ("ssrf", f"{base}/vuln/ssrf", ssrf_scanner.scan, (f"{base}/vuln/ssrf",), {"param": "url", "callback_base_url": base}),
            (
                "blind_xss",
                f"{base}/vuln/blind-xss-execute",
                blind_xss.scan,
                (f"{base}/vuln/blind-xss-execute",),
                {"param": "message", "callback_base_url": base},
            ),
            ("openapi", f"{base}/openapi.json", openapi_scanner.scan, (base,), {"document_url": f"{base}/openapi.json", "probe_limit": "10"}),
            ("graphql_modern", f"{base}/graphql-modern", graphql_scanner.scan, (base,), {"endpoint": f"{base}/graphql-modern"}),
            (
                "authorization_matrix",
                f"{base}/roles/admin-vuln",
                authorization_matrix_scanner.scan,
                (base,),
                {"endpoints": "/roles/admin-vuln", "max_endpoints": "5", "_runtime_ephemeral": auth_profiles},
            ),
            ("oidc_risky", f"{base}/oidc-risky", oidc_scanner.scan, (base,), {"discovery_url": f"{base}/oidc-risky"}),
        ]

        results = []
        for index, (name, target, scanner, args, kwargs) in enumerate(cases, start=1):
            runtime_ephemeral = kwargs.pop("_runtime_ephemeral", None)
            results.append(run_case(index, name, target, scanner, *args, runtime_ephemeral=runtime_ephemeral, **kwargs))

    print(json.dumps({"results": results}, indent=2))
    failed = [item for item in results if not item["vulnerable"] or item["status"] not in {"confirmed", "potential"}]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
