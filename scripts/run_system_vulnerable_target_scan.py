from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.conftest import lab_server


@contextmanager
def running_lab():
    fixture = lab_server.__wrapped__()
    base_url = next(fixture)
    try:
        yield base_url
    finally:
        fixture.close()


def load_app(database_path: Path, lab_base_url: str):
    os.environ["DATABASE_PATH"] = str(database_path)
    os.environ["FLASK_SECRET_KEY"] = "system-lab-flask-secret-abcdefghijklmnopqrstuvwxyz"
    os.environ["JWT_SECRET_KEY"] = "system-lab-jwt-secret-abcdefghijklmnopqrstuvwxyz"
    os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
    os.environ["OAST_ALLOW_PRIVATE_CALLBACKS"] = "true"
    os.environ["OAST_PUBLIC_BASE_URL"] = lab_base_url
    os.environ["SCANNER_TIMEOUT"] = "4"

    import database
    import app as app_module

    importlib.reload(database)
    app_module = importlib.reload(app_module)
    app_module.app.config.update(TESTING=True)
    return app_module


def csrf(client, path="/login") -> str:
    client.get(path)
    with client.session_transaction() as session:
        return session["_csrf_token"]


def register_and_login(app_module):
    client = app_module.app.test_client()
    email = f"system-lab-{int(time.time())}@example.com"
    token = csrf(client, "/register")
    response = client.post(
        "/register",
        data={
            "email": email,
            "password": "SecurePass123",
            "confirm_password": "SecurePass123",
            "csrf_token": token,
        },
    )
    if response.status_code != 302:
        raise RuntimeError(f"register failed: {response.status_code} {response.get_data(as_text=True)}")

    token = csrf(client, "/login")
    response = client.post(
        "/login",
        data={"email": email, "password": "SecurePass123", "csrf_token": token},
    )
    if response.status_code != 302:
        raise RuntimeError(f"login failed: {response.status_code} {response.get_data(as_text=True)}")

    with client.session_transaction() as session:
        return client, session["_csrf_token"], email


def wait_for_scan(client, scan_id: int, timeout_seconds: float = 35.0) -> dict:
    terminal = {"done", "failed", "cancelled", "budget_exhausted"}
    deadline = time.monotonic() + timeout_seconds
    last = {}
    while time.monotonic() < deadline:
        response = client.get(f"/scan-status/{scan_id}")
        if response.status_code != 200:
            raise RuntimeError(f"status failed for scan {scan_id}: {response.status_code}")
        last = response.get_json()["scan"]
        if last.get("status") in terminal:
            return last
        time.sleep(0.15)
    raise TimeoutError(f"scan {scan_id} did not finish: {last}")


def submit_scan(client, csrf_token: str, body: dict) -> tuple[int, dict]:
    response = client.post("/scan-live", json=body, headers={"X-CSRF-Token": csrf_token})
    if response.status_code != 202:
        raise RuntimeError(f"scan submit failed: {response.status_code} {response.get_data(as_text=True)}")
    scan_id = response.get_json()["scan_id"]
    return scan_id, wait_for_scan(client, scan_id)


def summarize_scan(name: str, target: str, scan_id: int, payload: dict) -> dict:
    results = payload.get("results", [])
    findings = [
        {
            "scanner": item.get("name"),
            "status": item.get("status"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "summary": str(item.get("result", ""))[:180],
        }
        for item in results
        if item.get("vulnerable") or item.get("status") in {"confirmed", "potential"}
    ]
    return {
        "case": name,
        "scan_id": scan_id,
        "target": target,
        "status": payload.get("status"),
        "progress": payload.get("progress"),
        "request_count": payload.get("request_count"),
        "finding_count": len(findings),
        "findings": findings,
    }


def main() -> int:
    with running_lab() as lab_base:
        with tempfile.TemporaryDirectory(prefix="cyberscan-system-lab-") as tmp:
            app_module = load_app(Path(tmp) / "scanner.db", lab_base)
            client, csrf_token, email = register_and_login(app_module)
            cases = [
                {
                    "name": "reflected_xss_and_injection",
                    "body": {
                        "url": f"{lab_base}/vuln/html",
                        "vulns": ["xss", "html_injection"],
                        "authorized": True,
                        "request_budget": 40,
                        "scanner_inputs": {
                            "xss": {"param": "q"},
                            "html_injection": {"param": "q"},
                        },
                    },
                },
                {
                    "name": "sql_injection",
                    "body": {
                        "url": f"{lab_base}/vuln/sqli",
                        "vulns": ["sql_injection"],
                        "authorized": True,
                        "request_budget": 50,
                        "scanner_inputs": {
                            "sql_injection": {"param": "id"},
                        },
                    },
                },
                {
                    "name": "path_traversal",
                    "body": {
                        "url": f"{lab_base}/vuln/traversal",
                        "vulns": ["path_traversal"],
                        "authorized": True,
                        "request_budget": 20,
                        "scanner_inputs": {
                            "path_traversal": {
                                "param": "file",
                                "canary_path": "../private/cyberscan-canary.txt",
                                "expected_marker": "CYBERSCAN_CANARY",
                            },
                        },
                    },
                },
                {
                    "name": "web_clickjacking",
                    "body": {
                        "url": f"{lab_base}/vuln/clickjacking",
                        "vulns": ["clickjacking_scanner"],
                        "authorized": True,
                        "request_budget": 40,
                    },
                },
                {
                    "name": "cors",
                    "body": {
                        "url": f"{lab_base}/vuln/cors",
                        "vulns": ["cors_scanner"],
                        "authorized": True,
                        "request_budget": 20,
                    },
                },
                {
                    "name": "csrf",
                    "body": {
                        "url": f"{lab_base}/vuln/csrf",
                        "vulns": ["csrf_scan"],
                        "authorized": True,
                        "request_budget": 20,
                    },
                },
                {
                    "name": "info_disclosure",
                    "body": {
                        "url": f"{lab_base}/vuln/info",
                        "vulns": ["info_scan"],
                        "authorized": True,
                        "request_budget": 20,
                    },
                },
                {
                    "name": "host_header",
                    "body": {
                        "url": f"{lab_base}/vuln/host-redirect",
                        "vulns": ["host_header_scanner"],
                        "authorized": True,
                        "request_budget": 20,
                    },
                },
                {
                    "name": "auth_and_access",
                    "body": {
                        "url": f"{lab_base}/vuln/idor",
                        "vulns": ["idor", "weak_password_scanner", "auth_scanner", "rate_limit"],
                        "authorized": True,
                        "request_budget": 60,
                        "scanner_inputs": {
                            "idor": {
                                "param": "id",
                                "authorized_id": "1001",
                                "test_id": "1002",
                                "private_marker": "private_marker",
                                "auth_header_name": "X-Test-Authorization",
                                "auth_header_value": "fixture-secret-token",
                            },
                            "weak_password_scanner": {
                                "login_url": f"{lab_base}/vuln/login",
                                "username_field": "username",
                                "password_field": "password",
                                "test_username": "test-user",
                                "test_password": "Password1",
                                "success_marker": "Welcome",
                            },
                            "auth_scanner": {
                                "login_url": f"{lab_base}/vuln/auth",
                                "test_username": "security-test",
                                "failure_marker": "Invalid credentials",
                            },
                        },
                    },
                },
                {
                    "name": "stored_callback_and_upload",
                    "body": {
                        "url": f"{lab_base}/vuln/stored",
                        "vulns": ["stored_xss_scanner", "file_upload"],
                        "authorized": True,
                        "request_budget": 60,
                        "scanner_inputs": {
                            "stored_xss_scanner": {
                                "submit_url": f"{lab_base}/vuln/stored",
                                "view_url": f"{lab_base}/vuln/stored-view",
                                "param_name": "comment",
                            },
                            "file_upload": {
                                "upload_url": f"{lab_base}/vuln/upload",
                                "file_field": "file",
                                "public_url_template": f"{lab_base}/public/{{filename}}",
                            },
                        },
                    },
                },
                {
                    "name": "ssrf",
                    "body": {
                        "url": f"{lab_base}/vuln/ssrf",
                        "vulns": ["ssrf_scanner"],
                        "authorized": True,
                        "request_budget": 20,
                        "scanner_inputs": {
                            "ssrf_scanner": {"param": "url", "callback_base_url": lab_base},
                        },
                    },
                },
                {
                    "name": "blind_xss",
                    "body": {
                        "url": f"{lab_base}/vuln/blind-xss-execute",
                        "vulns": ["blind_xss"],
                        "authorized": True,
                        "request_budget": 20,
                        "scanner_inputs": {
                            "blind_xss": {"param": "message", "callback_base_url": lab_base},
                        },
                    },
                },
                {
                    "name": "api_and_oidc",
                    "body": {
                        "url": f"{lab_base}/modern/",
                        "vulns": ["openapi_scanner", "graphql_scanner", "authorization_matrix_scanner", "oidc_scanner"],
                        "authorized": True,
                        "scan_mode": "modern",
                        "request_budget": 80,
                        "scanner_inputs": {
                            "openapi_scanner": {"document_url": f"{lab_base}/openapi.json", "probe_limit": "10"},
                            "graphql_scanner": {"endpoint": f"{lab_base}/graphql-modern"},
                            "authorization_matrix_scanner": {"endpoints": "/roles/admin-vuln", "max_endpoints": "5"},
                            "oidc_scanner": {"discovery_url": f"{lab_base}/oidc-risky"},
                        },
                        "auth_profiles": [
                            {"name": "user", "expected_access": "user", "headers": {"Authorization": "Bearer low-role"}},
                            {"name": "admin", "expected_access": "admin", "headers": {"Authorization": "Bearer high-role"}},
                        ],
                    },
                },
            ]

            summaries = []
            for case in cases:
                scan_id, payload = submit_scan(client, csrf_token, case["body"])
                summaries.append(summarize_scan(case["name"], case["body"]["url"], scan_id, payload))

    print(json.dumps({"lab": lab_base, "user": email, "scans": summaries}, indent=2))
    failed = [scan for scan in summaries if scan["status"] != "done" or scan["finding_count"] == 0]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
