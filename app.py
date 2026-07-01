from __future__ import annotations

import hmac
import inspect
import json
import os
import re
import secrets
import time
from datetime import timedelta
from io import BytesIO
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, send_file, session
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, verify_jwt_in_request
from flask_socketio import SocketIO, emit, join_room
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from database import audit, connect, init_db, utc_now
from services.auth_profiles import AuthProfileError, parse_auth_profiles, parse_browser_storage_state
from services.distributed_queue import QueueConfigurationError, get_queue, redis_backend_enabled
from main import load_scanners
from routes_ai import ai_bp
from services.oast import is_registered, record_hit
from services.scan_manager import active_count_for_user, cancel as cancel_managed_scan, register as register_scan_runtime, submit as submit_scan_job
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, ScanRuntime, activate_runtime
from vulnerabilities.common import UnsafeTargetError, env_bool as scanner_env_bool, validate_target_url

load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def runtime_secret(name: str) -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    # Safe for local development. setup scripts generate persistent values.
    return secrets.token_urlsafe(48)


app = Flask(__name__)
app.config.update(
    SECRET_KEY=runtime_secret("FLASK_SECRET_KEY"),
    JWT_SECRET_KEY=runtime_secret("JWT_SECRET_KEY"),
    SESSION_COOKIE_NAME="cyberscan_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_bool("SESSION_COOKIE_SECURE", False),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", str(4 * 1024 * 1024))),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.getenv("SESSION_LIFETIME_HOURS", "8"))),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=int(os.getenv("JWT_ACCESS_MINUTES", "30"))),
)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
allowed_origins = [item.strip() for item in os.getenv("SOCKET_ALLOWED_ORIGINS", "").split(",") if item.strip()]
socket_message_queue = os.getenv("SOCKETIO_MESSAGE_QUEUE", "").strip()
if not socket_message_queue and redis_backend_enabled():
    socket_message_queue = os.getenv("REDIS_URL", "").strip()
socketio = SocketIO(
    app,
    cors_allowed_origins=allowed_origins or None,
    async_mode="threading",
    manage_session=False,
    message_queue=socket_message_queue or None,
)

init_db()
app.register_blueprint(ai_bp)

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
OWASP_BY_SCANNER = {
    "sql_injection": "A03: Injection",
    "xss": "A03: Injection",
    "stored_xss_scanner": "A03: Injection",
    "blind_xss": "A03: Injection",
    "html_injection": "A03: Injection",
    "idor": "A01: Broken Access Control",
    "path_traversal": "A01: Broken Access Control",
    "file_upload": "A01: Broken Access Control",
    "open_redirect_scanner": "A01: Broken Access Control",
    "ssrf_scanner": "A10: Server-Side Request Forgery",
    "auth_scanner": "A07: Identification and Authentication Failures",
    "weak_password_scanner": "A07: Identification and Authentication Failures",
    "rate_limit": "A07: Identification and Authentication Failures",
    "cors_scanner": "A05: Security Misconfiguration",
    "csrf_scan": "A05: Security Misconfiguration",
    "clickjacking_scanner": "A05: Security Misconfiguration",
    "host_header_scanner": "A05: Security Misconfiguration",
    "graphql_scanner": "A05: Security Misconfiguration",
    "dir_scan": "A05: Security Misconfiguration",
    "info_scan": "A05: Security Misconfiguration",
    "modern_spa_scanner": "A05: Security Misconfiguration",
    "openapi_scanner": "A05: Security Misconfiguration",
    "websocket_scanner": "A05: Security Misconfiguration",
    "grpc_scanner": "A05: Security Misconfiguration",
    "authorization_matrix_scanner": "A01: Broken Access Control",
    "oidc_scanner": "A07: Identification and Authentication Failures",
}

ASVS_BY_SCANNER = {
    "sql_injection": "ASVS 5.0 — Encoding and Sanitization",
    "xss": "ASVS 5.0 — Encoding and Sanitization",
    "stored_xss_scanner": "ASVS 5.0 — Encoding and Sanitization",
    "blind_xss": "ASVS 5.0 — Encoding and Sanitization",
    "html_injection": "ASVS 5.0 — Encoding and Sanitization",
    "path_traversal": "ASVS 5.0 — File Handling",
    "file_upload": "ASVS 5.0 — File Handling",
    "auth_scanner": "ASVS 5.0 — Authentication",
    "weak_password_scanner": "ASVS 5.0 — Authentication",
    "rate_limit": "ASVS 5.0 — Authentication",
    "oidc_scanner": "ASVS 5.0 — OAuth and OpenID Connect",
    "csrf_scan": "ASVS 5.0 — Session Management",
    "idor": "ASVS 5.0 — Authorization",
    "authorization_matrix_scanner": "ASVS 5.0 — Authorization",
    "open_redirect_scanner": "ASVS 5.0 — Authorization",
    "ssrf_scanner": "ASVS 5.0 — Web Service Security",
    "cors_scanner": "ASVS 5.0 — Web Frontend Security",
    "clickjacking_scanner": "ASVS 5.0 — Web Frontend Security",
    "host_header_scanner": "ASVS 5.0 — HTTP Security",
    "websocket_scanner": "ASVS 5.0 — WebSocket Security",
    "openapi_scanner": "ASVS 5.0 — API and Web Service Security",
    "graphql_scanner": "ASVS 5.0 — API and Web Service Security",
    "grpc_scanner": "ASVS 5.0 — API and Web Service Security",
    "modern_spa_scanner": "ASVS 5.0 — Web Frontend Security",
    "dir_scan": "ASVS 5.0 — Configuration",
    "info_scan": "ASVS 5.0 — Error Handling and Logging",
}

RATE_LIMITS: dict[str, list[float]] = {}
AUTH_RATE_LIMIT_WINDOW = int(os.getenv("AUTH_RATE_LIMIT_WINDOW", "300"))
AUTH_RATE_LIMIT_MAX = int(os.getenv("AUTH_RATE_LIMIT_MAX", "5"))
MAX_ACTIVE_SCANS_PER_USER = int(os.getenv("MAX_ACTIVE_SCANS_PER_USER", "2"))
DEFAULT_REQUEST_BUDGET = int(os.getenv("DEFAULT_REQUEST_BUDGET", "120"))
MAX_REQUEST_BUDGET = int(os.getenv("MAX_REQUEST_BUDGET", "500"))
FORBIDDEN_GLOBAL_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}


def csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def enforce_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if request.path.startswith(("/socket.io/", "/oast/")) or request.endpoint in {"api_login", "api_register"}:
        return None
    if request.headers.get("Authorization", "").lower().startswith("bearer "):
        try:
            verify_jwt_in_request()
            return None
        except Exception:
            return jsonify({"error": "Invalid bearer token"}), 401
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(str(supplied), str(expected)):
        return jsonify({"error": "Invalid or missing CSRF token"}), 400
    return None


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    if env_bool("ENABLE_HSTS", False):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if session.get("user_id") or request.path.startswith(("/api/", "/scan-", "/login", "/register")):
        response.headers.setdefault("Cache-Control", "no-store, max-age=0")
        response.headers.setdefault("Pragma", "no-cache")
    return response


def rate_limit_key(action: str, identifier: str) -> str:
    client_ip = request.remote_addr or "unknown"
    if env_bool("TRUST_PROXY_HEADERS", False):
        client_ip = (request.headers.get("X-Forwarded-For") or client_ip).split(",")[0].strip()
    return f"{action}:{client_ip}:{identifier or 'unknown'}"


def is_rate_limited(action: str, identifier: str) -> bool:
    now = time.time()
    key = rate_limit_key(action, identifier)
    timestamps = [stamp for stamp in RATE_LIMITS.get(key, []) if now - stamp < AUTH_RATE_LIMIT_WINDOW]
    if len(timestamps) >= AUTH_RATE_LIMIT_MAX:
        RATE_LIMITS[key] = timestamps
        return True
    timestamps.append(now)
    RATE_LIMITS[key] = timestamps
    return False


def password_error(password: str) -> str | None:
    if len(password) < 10:
        return "Password must contain at least 10 characters."
    checks = [any(ch.islower() for ch in password), any(ch.isupper() for ch in password), any(ch.isdigit() for ch in password)]
    if sum(checks) < 3:
        return "Password must contain uppercase, lowercase, and numeric characters."
    return None


def request_payload() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else request.form.to_dict()


def client_ip() -> str:
    value = request.remote_addr or "unknown"
    if env_bool("TRUST_PROXY_HEADERS", False):
        value = (request.headers.get("X-Forwarded-For") or value).split(",")[0].strip()
    return value[:128]


def parse_string_map(value, *, label: str, max_items: int = 30) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} must be a JSON object.") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    if len(value) > max_items:
        raise ValueError(f"{label} contains too many entries.")
    parsed: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip()
        item = str(raw_value).strip()
        if not key or len(key) > 128 or len(item) > 4096:
            raise ValueError(f"{label} contains an invalid key or value.")
        if "\r" in key or "\n" in key or "\r" in item or "\n" in item:
            raise ValueError(f"{label} cannot contain line breaks.")
        parsed[key] = item
    return parsed


def sanitize_global_headers(value) -> dict[str, str]:
    headers = parse_string_map(value, label="HTTP headers")
    forbidden = [key for key in headers if key.lower() in FORBIDDEN_GLOBAL_HEADERS]
    if forbidden:
        raise ValueError(f"These global headers are not allowed: {', '.join(forbidden)}")
    return headers


def configured_host_allowed(hostname: str) -> bool:
    configured = [item.strip().lower() for item in os.getenv("SCAN_ALLOWED_HOSTS", "").split(",") if item.strip()]
    if not configured:
        return True
    host = hostname.lower().rstrip(".")
    for pattern in configured:
        pattern = pattern.rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif host == pattern:
            return True
    return False


def target_in_user_scope(user_id: int, hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    conn = connect()
    rows = conn.execute(
        "SELECT hostname_pattern,include_subdomains FROM target_scopes WHERE user_id=? AND is_active=1",
        (user_id,),
    ).fetchall()
    conn.close()
    if not rows:
        return not env_bool("REQUIRE_TARGET_SCOPE", False)
    for row in rows:
        pattern = str(row["hostname_pattern"]).lower().rstrip(".")
        if host == pattern or (row["include_subdomains"] and host.endswith("." + pattern)):
            return True
    return False


def calculate_risk_score(results: list[dict]) -> float:
    weights = {"Critical": 40.0, "High": 25.0, "Medium": 12.0, "Low": 5.0, "Info": 1.0}
    confidence = {"High": 1.0, "Medium": 0.7, "Low": 0.35}
    score = 0.0
    for item in results:
        if item.get("status") not in {"confirmed", "potential"}:
            continue
        status_factor = 1.0 if item.get("status") == "confirmed" else 0.45
        score += weights.get(normalize_severity(item.get("severity")), 1.0) * confidence.get(str(item.get("confidence")), 0.35) * status_factor
    return round(min(100.0, score), 1)


def scanner_key(name: str) -> str:
    return str(name or "unknown").strip().lower().replace("-", "_").replace(" ", "_")


def display_scanner_name(name: str) -> str:
    return " ".join(part.capitalize() for part in str(name or "Unknown Scanner").replace("_", " ").split())


def normalize_severity(value: str | None) -> str:
    text = str(value or "Info").strip().lower()
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    return mapping.get(text, "Info")


def owasp_category_for(name: str) -> str:
    return OWASP_BY_SCANNER.get(scanner_key(name), "A05: Security Misconfiguration")


def asvs_category_for(name: str) -> str:
    return ASVS_BY_SCANNER.get(scanner_key(name), "ASVS 5.0 — Configuration")


def safe_json_loads(value):
    if isinstance(value, (list, dict)):
        return value
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []


def normalize_scanner_result(scanner_name: str, raw_result) -> dict:
    if not isinstance(raw_result, dict):
        raw_result = {"vulnerable": False, "status": "error", "result": str(raw_result), "severity": "Info", "confidence": "Low"}
    result = dict(raw_result)
    result["name"] = scanner_name
    result["severity"] = normalize_severity(result.get("severity"))
    result.setdefault("vulnerable", False)
    result.setdefault("status", "confirmed" if result["vulnerable"] else "not_vulnerable")
    result.setdefault("confidence", "Low")
    result.setdefault("result", "No details available")
    result.setdefault("evidence", {})
    result.setdefault("recommendation", "")
    result.setdefault("endpoint", "")
    result.setdefault("parameter", "")
    result.setdefault("cwe", "")
    result.setdefault("cvss", 0.0)
    result.setdefault("requests_made", 0)
    return result


def is_finding(item: dict) -> bool:
    status = str(item.get("status") or "").strip().lower()
    if status:
        return status in {"confirmed", "potential"}
    return bool(item.get("vulnerable"))


def result_has_status(item: dict, statuses: set[str]) -> bool:
    return str(item.get("status") or "").strip().lower() in statuses


def normalize_finding(item: dict) -> dict:
    name = item.get("name", "Unknown Scanner")
    evidence = item.get("evidence") or {}
    if isinstance(evidence, (dict, list)):
        evidence_text = json.dumps(evidence, ensure_ascii=False, indent=2)
    else:
        evidence_text = str(evidence)
    return {
        "scanner": display_scanner_name(name),
        "scanner_key": scanner_key(name),
        "severity": normalize_severity(item.get("severity")),
        "description": str(item.get("result") or "No details available"),
        "evidence": evidence_text or "N/A",
        "recommendation": str(item.get("recommendation") or "Review and manually validate the affected endpoint."),
        "owasp": owasp_category_for(name),
        "asvs": asvs_category_for(name),
        "confidence": str(item.get("confidence") or "Low"),
        "status": str(item.get("status") or ("confirmed" if item.get("vulnerable") else "unknown")),
        "endpoint": str(item.get("endpoint") or ""),
        "parameter": str(item.get("parameter") or ""),
        "cwe": str(item.get("cwe") or ""),
        "cvss": float(item.get("cvss") or 0.0),
    }


def normalize_scan_results(raw_results) -> list[dict]:
    parsed = safe_json_loads(raw_results)
    if isinstance(parsed, dict):
        parsed = [parsed]
    return [normalize_finding(item) for item in parsed if isinstance(item, dict) and is_finding(item)]


def normalize_scan_checks(raw_results, statuses: set[str]) -> list[dict]:
    parsed = safe_json_loads(raw_results)
    if isinstance(parsed, dict):
        parsed = [parsed]
    return [
        normalize_finding(item)
        for item in parsed
        if isinstance(item, dict) and result_has_status(item, statuses)
    ]


def build_sarif(scan_row) -> dict:
    raw_results = safe_json_loads(scan_row["result"])
    findings = [item for item in raw_results if isinstance(item, dict) and is_finding(item)]
    rules: dict[str, dict] = {}
    sarif_results = []
    level_map = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    for item in findings:
        rule_id = scanner_key(item.get("name") or "unknown")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": display_scanner_name(rule_id),
                "shortDescription": {"text": str(item.get("result") or display_scanner_name(rule_id))[:300]},
                "help": {"text": str(item.get("recommendation") or "Review and validate the finding.")[:2000]},
                "properties": {
                    "security-severity": str(float(item.get("cvss") or 0.0)),
                    "tags": [owasp_category_for(rule_id), asvs_category_for(rule_id), str(item.get("cwe") or "")],
                },
            },
        )
        endpoint = str(item.get("endpoint") or scan_row["target"])
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(normalize_severity(item.get("severity")), "note"),
                "message": {"text": str(item.get("result") or "Security finding")[:4000]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": endpoint}}}],
                "properties": {
                    "status": str(item.get("status") or "unknown"),
                    "confidence": str(item.get("confidence") or "Low"),
                    "severity": normalize_severity(item.get("severity")),
                    "parameter": str(item.get("parameter") or ""),
                    "evidence": item.get("evidence") or {},
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberScan Professional",
                        "version": str(scan_row["tool_version"] or "5.0.0"),
                        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "scanId": scan_row["id"],
                    "target": scan_row["target"],
                    "status": scan_row["status"],
                    "authorizedTestingOnly": True,
                },
            }
        ],
    }


def highest_severity(findings: list[dict]) -> str:
    return max((item["severity"] for item in findings), key=lambda value: SEVERITY_ORDER.get(value, 0), default="Info")


def severity_distribution(findings: list[dict]) -> dict:
    result = {name: 0 for name in SEVERITY_ORDER}
    for item in findings:
        result[normalize_severity(item.get("severity"))] += 1
    return result


def scan_status_bucket(status: str) -> str:
    value = str(status or "done").lower()
    return "completed" if value in {"done", "complete", "completed"} else value


def group_findings_by_scanner(findings: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        groups.setdefault(finding["scanner"], []).append(finding)
    return [{"scanner": key, "findings": value} for key, value in groups.items()]


def artifact_summary(artifacts: dict | None) -> dict[str, int]:
    data = artifacts if isinstance(artifacts, dict) else {}
    browser = data.get("browser") if isinstance(data.get("browser"), dict) else {}
    openapi = data.get("openapi") if isinstance(data.get("openapi"), dict) else {}
    graphql = data.get("graphql") if isinstance(data.get("graphql"), dict) else {}
    grpc = data.get("grpc") if isinstance(data.get("grpc"), dict) else {}
    authz = data.get("authorization_matrix") if isinstance(data.get("authorization_matrix"), dict) else {}
    websockets = data.get("websockets") if isinstance(data.get("websockets"), list) else []
    return {
        "browser_pages": len(browser.get("pages_visited") or []),
        "network_requests": len(browser.get("requests") or []),
        "forms": len(browser.get("forms") or []),
        "websockets": max(len(browser.get("websocket_urls") or []), len(websockets)),
        "openapi_operations": len(openapi.get("operations") or []),
        "graphql_types": len(graphql.get("types") or []),
        "grpc_services": len(grpc.get("services") or []),
        "authorization_observations": len(authz.get("observations") or []),
    }


def build_sanitized_har(scan_row) -> dict:
    artifacts = safe_json_loads(scan_row["artifacts"]) if "artifacts" in scan_row.keys() else {}
    browser = artifacts.get("browser") if isinstance(artifacts, dict) else {}
    requests = browser.get("requests") if isinstance(browser, dict) else []
    entries = []
    for item in requests or []:
        if not isinstance(item, dict):
            continue
        entries.append({
            "startedDateTime": scan_row["started_at"] or scan_row["created_at"],
            "time": 0,
            "request": {
                "method": str(item.get("method") or "GET"),
                "url": str(item.get("url") or ""),
                "httpVersion": "",
                "headers": [],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": -1,
            },
            "response": {
                "status": int(item.get("status") or 0),
                "statusText": "",
                "httpVersion": "",
                "headers": [{"name": "Content-Type", "value": str(item.get("content_type") or "")}],
                "cookies": [],
                "content": {"size": 0, "mimeType": str(item.get("content_type") or "")},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
            "comment": "Sanitized CyberScan inventory; credentials and bodies are intentionally omitted.",
        })
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "CyberScan Professional", "version": str(scan_row["tool_version"] or "5.0.0")},
            "pages": [],
            "entries": entries,
            "comment": "Sanitized HAR-compatible network inventory. It does not include secrets, bodies, or timing data.",
        }
    }


def get_current_user_id():
    if session.get("user_id"):
        return int(session["user_id"])
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        return int(identity) if identity is not None else None
    except Exception:
        return None


def load_scanner_specs() -> list[dict]:
    specs = []
    for scanner in load_scanners():
        key = scanner.__name__.split(".")[-1]
        meta = getattr(scanner, "meta", {}) or {}
        specs.append(
            {
                "id": key,
                "name": meta.get("name", display_scanner_name(key)),
                "description": meta.get("description", ""),
                "severity": normalize_severity(meta.get("severity")),
                "category": meta.get("category", "General"),
                "inputs": getattr(scanner, "inputs", []) or [],
            }
        )
    return specs


def scanner_kwargs(scanner, scanner_id: str, payload_data: dict) -> dict:
    configured = payload_data.get("scanner_inputs", {})
    configured = configured.get(scanner_id, {}) if isinstance(configured, dict) else {}
    if not isinstance(configured, dict):
        configured = {}
    signature = inspect.signature(scanner.scan)
    kwargs = {}
    for name, param in list(signature.parameters.items())[1:]:
        if name in configured:
            value = configured[name]
            if isinstance(value, str):
                value = value.strip()[:4096]
            kwargs[name] = value
        elif param.default is inspect.Parameter.empty:
            kwargs[name] = ""
    return kwargs


def create_scan_record(
    user_id: int,
    url: str,
    selected: list[str],
    *,
    scan_mode: str,
    request_budget: int,
) -> int:
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (
            user_id,target,result,status,selected_scanners,scan_mode,progress,
            request_budget,tool_version,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            user_id, url, "[]", "queued", json.dumps(selected), scan_mode, 0,
            request_budget, "5.0.0", utc_now(),
        ),
    )
    scan_id = int(cursor.lastrowid)
    conn.commit()
    conn.close()
    return scan_id


def update_scan_progress(
    scan_id: int,
    *,
    results: list[dict] | None = None,
    artifacts: dict | None = None,
    status: str | None = None,
    progress: int | None = None,
    current_scanner: str | None = None,
    request_count: int | None = None,
    error_message: str | None = None,
    started: bool = False,
    completed: bool = False,
) -> None:
    assignments: list[str] = []
    values: list = []
    if results is not None:
        assignments.extend(["result=?", "risk_score=?"]); values.extend([json.dumps(results, ensure_ascii=False), calculate_risk_score(results)])
    if artifacts is not None:
        assignments.append("artifacts=?"); values.append(json.dumps(artifacts, ensure_ascii=False)[:2_000_000])
    if status is not None:
        assignments.append("status=?"); values.append(status)
    if progress is not None:
        assignments.append("progress=?"); values.append(max(0, min(100, int(progress))))
    if current_scanner is not None:
        assignments.append("current_scanner=?"); values.append(current_scanner[:120])
    if request_count is not None:
        assignments.append("request_count=?"); values.append(max(0, int(request_count)))
    if error_message is not None:
        assignments.append("error_message=?"); values.append(error_message[:2000])
    if started:
        assignments.append("started_at=COALESCE(started_at,?)"); values.append(utc_now())
    if completed:
        assignments.append("completed_at=?"); values.append(utc_now())
    if not assignments:
        return
    values.append(scan_id)
    conn = connect()
    conn.execute(f"UPDATE scans SET {', '.join(assignments)} WHERE id=?", values)
    conn.commit()
    conn.close()


def get_user_scan(scan_id: int, user_id: int):
    conn = connect()
    row = conn.execute(
        """
        SELECT scans.*, users.email
        FROM scans JOIN users ON users.id=scans.user_id
        WHERE scans.id=? AND scans.user_id=?
        """,
        (scan_id, user_id),
    ).fetchone()
    conn.close()
    return row


def serialize_scan_row(row, *, include_results: bool = True) -> dict:
    results = safe_json_loads(row["result"]) if include_results else []
    return {
        "id": row["id"],
        "target": row["target"],
        "results": results,
        "artifacts": safe_json_loads(row["artifacts"]) if "artifacts" in row.keys() else {},
        "status": row["status"],
        "progress": row["progress"],
        "current_scanner": row["current_scanner"],
        "request_count": row["request_count"],
        "request_budget": row["request_budget"],
        "risk_score": row["risk_score"],
        "security_score": max(0, round(100 - float(row["risk_score"] or 0), 1)),
        "error_message": row["error_message"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "selected_scanners": safe_json_loads(row["selected_scanners"]),
        "scan_mode": row["scan_mode"],
        "tool_version": row["tool_version"],
    }


def user_room(user_id: int) -> str:
    return f"user:{user_id}"


def scan_room(scan_id: int) -> str:
    return f"scan:{scan_id}"


def emit_log(message: str, user_id: int, scan_id: int) -> None:
    payload = {"message": message, "scan_id": scan_id}
    socketio.emit("log", payload, to=user_room(user_id))
    socketio.emit("log", payload, to=scan_room(scan_id))


def pdf_paragraph(value, style):
    return Paragraph(escape(str(value if value is not None else "N/A")), style)


def build_scan_report_pdf(scan: dict) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#64748B"), leading=11))
    elements = [
        pdf_paragraph("CyberScan Professional Security Report", styles["Title"]),
        pdf_paragraph("Authorized testing only. Potential findings require manual validation.", styles["SmallMuted"]),
        Spacer(1, 14),
        pdf_paragraph("Executive Summary", styles["Heading1"]),
        pdf_paragraph(
            f'The scan identified {scan["findings_count"]} confirmed or potential security finding(s). '
            f'The highest severity was {scan["highest_severity"]}, with an aggregate risk score of {scan.get("risk_score", 0)}/100.',
            styles["BodyText"],
        ),
        pdf_paragraph(
            "Aggregate risk score based on severity, confidence, and finding status. It is different from CVSS.",
            styles["SmallMuted"],
        ),
        Spacer(1, 12),
        pdf_paragraph("Target Information", styles["Heading1"]),
    ]
    target_table = Table(
        [
            ["Target", scan["target"]],
            ["User", scan.get("email", "N/A")],
            ["Created", scan["created_at"]],
            ["Completed", scan.get("completed_at") or "N/A"],
            ["Status", scan["status"]],
        ],
        colWidths=[120, 360],
    )
    target_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E2E8F0")), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 6)]))
    selected_scanners = ", ".join(scan.get("selected_scanners") or []) or "Not recorded"
    config_table = Table(
        [
            ["Scan mode", scan.get("scan_mode", "standard")],
            ["Selected scanners", selected_scanners],
            ["HTTP requests", f'{scan.get("request_count", 0)} / {scan.get("request_budget", "N/A")}'],
            ["Tool version", scan.get("tool_version", "5.0.0")],
        ],
        colWidths=[120, 360],
    )
    config_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E2E8F0")), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 6)]))
    distribution = scan.get("severity_distribution") or {}
    findings_summary = Table(
        [
            ["Security findings", scan["findings_count"]],
            ["Highest severity", scan["highest_severity"]],
            ["Risk score", f'{scan.get("risk_score", 0)}/100'],
            ["Severity distribution", ", ".join(f"{name}: {distribution.get(name, 0)}" for name in SEVERITY_ORDER)],
        ],
        colWidths=[120, 360],
    )
    findings_summary.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E2E8F0")), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 6)]))
    elements += [
        target_table,
        Spacer(1, 12),
        pdf_paragraph("Scan Configuration", styles["Heading1"]),
        config_table,
        Spacer(1, 12),
        pdf_paragraph("Findings Summary", styles["Heading1"]),
        findings_summary,
        Spacer(1, 12),
        pdf_paragraph("Detailed Findings", styles["Heading1"]),
    ]
    if not scan["groups"]:
        elements.append(pdf_paragraph("No confirmed or potential security findings were saved.", styles["BodyText"]))
    for group in scan["groups"]:
        elements.append(pdf_paragraph(group["scanner"], styles["Heading2"]))
        for finding in group["findings"]:
            data = [
                ["Severity / status", f'{finding["severity"]} / {finding["status"]}'],
                ["Confidence", finding["confidence"]],
                ["OWASP / ASVS", f'{finding["owasp"]} / {finding["asvs"]}'],
                ["CWE / CVSS", f'{finding["cwe"] or "N/A"} / {finding["cvss"]:.1f}'],
                ["Endpoint", finding["endpoint"] or scan["target"]],
                ["Description", finding["description"]],
                ["Evidence", finding["evidence"]],
                ["Recommendation", finding["recommendation"]],
            ]
            table = Table([[pdf_paragraph(a, styles["BodyText"]), pdf_paragraph(b, styles["BodyText"])] for a, b in data], colWidths=[110, 370])
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
            elements += [table, Spacer(1, 10)]
    scanner_errors = scan.get("scanner_errors") or []
    inconclusive_checks = scan.get("inconclusive_checks") or []
    if scanner_errors or inconclusive_checks:
        elements += [Spacer(1, 8), pdf_paragraph("Scanner Errors / Inconclusive Checks", styles["Heading1"])]
        for check in scanner_errors + inconclusive_checks:
            check_table = Table(
                [
                    ["Scanner / status", f'{check["scanner"]} / {check["status"]}'],
                    ["Description", check["description"]],
                    ["Endpoint", check["endpoint"] or scan["target"]],
                    ["Evidence", check["evidence"]],
                ],
                colWidths=[120, 360],
            )
            check_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("PADDING", (0, 0), (-1, -1), 5)]))
            elements += [check_table, Spacer(1, 8)]
    elements += [
        pdf_paragraph("Limitations", styles["Heading1"]),
        pdf_paragraph("Automated scanning covers only the selected modules and supplied inputs. Potential and inconclusive results require manual validation. A clean report does not prove that the target is free of vulnerabilities.", styles["BodyText"]),
        Spacer(1, 8),
        pdf_paragraph("Recommendations", styles["Heading1"]),
    ]
    recommendations = list(dict.fromkeys(
        finding["recommendation"]
        for group in scan["groups"]
        for finding in group["findings"]
        if finding.get("recommendation")
    ))
    if recommendations:
        for index, recommendation in enumerate(recommendations, start=1):
            elements.append(pdf_paragraph(f"{index}. {recommendation}", styles["BodyText"]))
    else:
        elements.append(pdf_paragraph("Continue secure configuration reviews, dependency maintenance, monitoring, and authorized manual testing.", styles["BodyText"]))
    doc.build(elements)
    buffer.seek(0)
    return buffer


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if is_rate_limited("register", email):
            return "Too many registration attempts.", 429
        if not email or "@" not in email or len(email) > 254 or password != confirm:
            return "Valid email and matching passwords are required.", 400
        error = password_error(password)
        if error:
            return error, 400
        conn = connect()
        if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            conn.close()
            return "Email already exists.", 409
        cursor = conn.execute("INSERT INTO users (email,password) VALUES (?,?)", (email, bcrypt.generate_password_hash(password).decode()))
        user_id = int(cursor.lastrowid)
        conn.commit()
        conn.close()
        audit("auth.register", user_id=user_id, target_type="user", target_id=user_id, details={"email": email}, ip_address=client_ip())
        return redirect("/login")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if is_rate_limited("login", email):
            return "Too many login attempts.", 429
        conn = connect()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if user and user["is_active"] and bcrypt.check_password_hash(user["password"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            csrf_token()
            conn = connect(); conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (utc_now(), user["id"])); conn.commit(); conn.close()
            audit("auth.login", user_id=int(user["id"]), target_type="user", target_id=user["id"], ip_address=client_ip())
            return redirect("/dashboard")
        audit("auth.login_failed", target_type="user", target_id=email, ip_address=client_ip())
        return "Invalid email or password.", 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")
    if user_id:
        audit("auth.logout", user_id=int(user_id), target_type="user", target_id=user_id, ip_address=client_ip())
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/history")
def history():
    if not session.get("user_id"):
        return redirect("/login")
    conn = connect()
    rows = conn.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    conn.close()
    scans = []
    for row in rows:
        findings = normalize_scan_results(row["result"])
        scans.append({
            "id": row["id"], "target": row["target"], "results": findings,
            "findings_count": len(findings), "highest_severity": highest_severity(findings),
            "status": row["status"], "created_at": row["created_at"], "progress": row["progress"],
            "request_count": row["request_count"], "request_budget": row["request_budget"],
            "risk_score": row["risk_score"], "current_scanner": row["current_scanner"],
        })
    return render_template("history.html", scans=scans)


@app.route("/scan/<int:scan_id>")
def scan_details(scan_id: int):
    if not session.get("user_id"):
        return redirect("/login")
    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404
    findings = normalize_scan_results(row["result"])
    scanner_errors = normalize_scan_checks(row["result"], {"error"})
    inconclusive_checks = normalize_scan_checks(row["result"], {"inconclusive"})
    artifacts = safe_json_loads(row["artifacts"]) if "artifacts" in row.keys() else {}
    scan = {
        "id": row["id"], "target": row["target"], "status": row["status"],
        "created_at": row["created_at"], "started_at": row["started_at"],
        "completed_at": row["completed_at"], "email": row["email"],
        "findings_count": len(findings), "highest_severity": highest_severity(findings),
        "groups": group_findings_by_scanner(findings), "risk_score": row["risk_score"],
        "scanner_errors": scanner_errors, "inconclusive_checks": inconclusive_checks,
        "security_score": max(0, round(100 - float(row["risk_score"] or 0), 1)),
        "request_count": row["request_count"], "request_budget": row["request_budget"],
        "progress": row["progress"], "current_scanner": row["current_scanner"],
        "error_message": row["error_message"], "tool_version": row["tool_version"],
        "artifacts": artifacts, "artifact_summary": artifact_summary(artifacts),
    }
    return render_template("scan_details.html", scan=scan)


@app.route("/scan/<int:scan_id>/report")
def scan_report(scan_id: int):
    if not session.get("user_id"):
        return redirect("/login")
    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404
    findings = normalize_scan_results(row["result"])
    scanner_errors = normalize_scan_checks(row["result"], {"error"})
    inconclusive_checks = normalize_scan_checks(row["result"], {"inconclusive"})
    scan = {
        "id": row["id"], "target": row["target"], "status": row["status"],
        "created_at": row["created_at"], "completed_at": row["completed_at"], "email": row["email"],
        "findings_count": len(findings), "highest_severity": highest_severity(findings),
        "severity_distribution": severity_distribution(findings), "groups": group_findings_by_scanner(findings),
        "scanner_errors": scanner_errors, "inconclusive_checks": inconclusive_checks,
        "risk_score": row["risk_score"], "request_count": row["request_count"],
        "request_budget": row["request_budget"], "tool_version": row["tool_version"],
        "scan_mode": row["scan_mode"], "selected_scanners": safe_json_loads(row["selected_scanners"]),
    }
    audit("scan.export_pdf", user_id=int(session["user_id"]), target_type="scan", target_id=scan_id, ip_address=client_ip())
    return send_file(build_scan_report_pdf(scan), mimetype="application/pdf", as_attachment=True, download_name=f"cyberscan-{scan_id}-report.pdf")


@app.route("/scan/<int:scan_id>/export-json")
def scan_export_json(scan_id: int):
    if not session.get("user_id"):
        return redirect("/login")
    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404
    payload = serialize_scan_row(row)
    payload["scanner_results"] = payload.pop("results")
    buffer = BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode())
    audit("scan.export_json", user_id=int(session["user_id"]), target_type="scan", target_id=scan_id, ip_address=client_ip())
    return send_file(buffer, mimetype="application/json", as_attachment=True, download_name=f"cyberscan-{scan_id}-results.json")


@app.route("/scan/<int:scan_id>/export-sarif")
def scan_export_sarif(scan_id: int):
    if not session.get("user_id"):
        return redirect("/login")
    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404
    buffer = BytesIO(json.dumps(build_sarif(row), ensure_ascii=False, indent=2).encode())
    audit("scan.export_sarif", user_id=int(session["user_id"]), target_type="scan", target_id=scan_id, ip_address=client_ip())
    return send_file(
        buffer, mimetype="application/sarif+json", as_attachment=True,
        download_name=f"cyberscan-{scan_id}.sarif",
    )


@app.route("/scan/<int:scan_id>/export-artifacts")
def scan_export_artifacts(scan_id: int):
    if not session.get("user_id"):
        return redirect("/login")
    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404
    artifacts = safe_json_loads(row["artifacts"]) if "artifacts" in row.keys() else {}
    payload = {
        "scan_id": row["id"],
        "target": row["target"],
        "tool_version": row["tool_version"],
        "summary": artifact_summary(artifacts),
        "artifacts": artifacts,
        "secrets_omitted": True,
    }
    buffer = BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode())
    audit("scan.export_artifacts", user_id=int(session["user_id"]), target_type="scan", target_id=scan_id, ip_address=client_ip())
    return send_file(buffer, mimetype="application/json", as_attachment=True, download_name=f"cyberscan-{scan_id}-artifacts.json")


@app.route("/scan/<int:scan_id>/export-har")
def scan_export_har(scan_id: int):
    if not session.get("user_id"):
        return redirect("/login")
    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404
    buffer = BytesIO(json.dumps(build_sanitized_har(row), ensure_ascii=False, indent=2).encode())
    audit("scan.export_har", user_id=int(session["user_id"]), target_type="scan", target_id=scan_id, ip_address=client_ip())
    return send_file(buffer, mimetype="application/json", as_attachment=True, download_name=f"cyberscan-{scan_id}-sanitized.har")


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request_payload()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if is_rate_limited("api_register", email):
        return jsonify({"error": "Too many attempts"}), 429
    error = password_error(password)
    if not email or "@" not in email or len(email) > 254 or error:
        return jsonify({"error": error or "A valid email is required"}), 400
    conn = connect()
    if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        conn.close()
        return jsonify({"error": "User exists"}), 409
    cursor = conn.execute("INSERT INTO users (email,password) VALUES (?,?)", (email, bcrypt.generate_password_hash(password).decode()))
    user_id = int(cursor.lastrowid)
    conn.commit()
    conn.close()
    audit("auth.api_register", user_id=user_id, target_type="user", target_id=user_id, details={"email": email}, ip_address=client_ip())
    return jsonify({"message": "Registered"}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request_payload()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if is_rate_limited("api_login", email):
        return jsonify({"error": "Too many attempts"}), 429
    conn = connect()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if user and user["is_active"] and bcrypt.check_password_hash(user["password"], password):
        conn = connect(); conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (utc_now(), user["id"])); conn.commit(); conn.close()
        audit("auth.api_login", user_id=int(user["id"]), target_type="user", target_id=user["id"], ip_address=client_ip())
        return jsonify({"token": create_access_token(identity=str(user["id"])), "user_id": user["id"], "email": user["email"]})
    audit("auth.api_login_failed", target_type="user", target_id=email, ip_address=client_ip())
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/scanners")
def api_scanners():
    if not get_current_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"scanners": load_scanner_specs(), "csrf_token": csrf_token()})


@app.route("/api/scopes", methods=["GET", "POST"])
def api_scopes():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    if request.method == "GET":
        conn = connect()
        rows = conn.execute(
            "SELECT id,hostname_pattern,description,include_subdomains,is_active,created_at FROM target_scopes WHERE user_id=? ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
        conn.close()
        return jsonify({"scopes": [dict(row) for row in rows], "required": env_bool("REQUIRE_TARGET_SCOPE", False)})

    data = request_payload()
    raw = str(data.get("hostname", "")).strip().lower()
    if "://" in raw:
        raw = (urlparse(raw).hostname or "").lower()
    raw = raw.rstrip(".")
    if not raw or len(raw) > 253 or not re.fullmatch(r"[a-z0-9.-]+", raw) or ".." in raw:
        return jsonify({"error": "A valid hostname is required; wildcards are controlled by include_subdomains."}), 400
    include_subdomains = 1 if data.get("include_subdomains") is True else 0
    description = str(data.get("description", "")).strip()[:500]
    try:
        # Resolution and network policy are checked at scope creation as well as scan time.
        validate_target_url(f"https://{raw}")
    except UnsafeTargetError as exc:
        return jsonify({"error": str(exc)}), 400
    conn = connect()
    try:
        cursor = conn.execute(
            "INSERT INTO target_scopes (user_id,hostname_pattern,description,include_subdomains,is_active,created_at) VALUES (?,?,?,?,1,?)",
            (int(user_id), raw, description, include_subdomains, utc_now()),
        )
        scope_id = int(cursor.lastrowid)
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"error": "This hostname is already in your scope."}), 409
    conn.close()
    audit("scope.created", user_id=int(user_id), target_type="scope", target_id=scope_id, details={"hostname": raw, "include_subdomains": bool(include_subdomains)}, ip_address=client_ip())
    return jsonify({"id": scope_id, "hostname_pattern": raw, "include_subdomains": bool(include_subdomains)}), 201


@app.route("/api/scopes/<int:scope_id>", methods=["DELETE"])
def api_scope_delete(scope_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    conn = connect()
    cursor = conn.execute("DELETE FROM target_scopes WHERE id=? AND user_id=?", (scope_id, int(user_id)))
    conn.commit(); conn.close()
    if cursor.rowcount == 0:
        return jsonify({"error": "Not found"}), 404
    audit("scope.deleted", user_id=int(user_id), target_type="scope", target_id=scope_id, ip_address=client_ip())
    return jsonify({"message": "Scope deleted"})


@app.route("/api/audit")
def api_audit():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    conn = connect()
    rows = conn.execute(
        "SELECT action,target_type,target_id,details,ip_address,created_at FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 100",
        (int(user_id),),
    ).fetchall()
    conn.close()
    return jsonify({"events": [{**dict(row), "details": safe_json_loads(row["details"])} for row in rows]})


@app.route("/api/history")
def api_history():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    conn = connect()
    rows = conn.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC", (int(user_id),)).fetchall()
    conn.close()
    return jsonify({"scans": [serialize_scan_row(row) for row in rows]})


@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    conn = connect()
    rows = conn.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC", (int(user_id),)).fetchall()
    conn.close()
    all_findings = []
    counts: dict[str, int] = {}
    recent = []
    for row in rows:
        findings = normalize_scan_results(row["result"])
        all_findings.extend(findings)
        bucket = scan_status_bucket(row["status"])
        counts[bucket] = counts.get(bucket, 0) + 1
        if len(recent) < 5:
            recent.append({
                "id": row["id"], "target": row["target"], "status": bucket,
                "created_at": row["created_at"], "findings_count": len(findings),
                "highest_severity": highest_severity(findings), "progress": row["progress"],
                "current_scanner": row["current_scanner"], "request_count": row["request_count"],
                "request_budget": row["request_budget"], "risk_score": row["risk_score"],
            })
    active = counts.get("running", 0) + counts.get("queued", 0) + counts.get("cancelling", 0)
    failed = counts.get("failed", 0) + counts.get("interrupted", 0) + counts.get("budget_exhausted", 0)
    return jsonify({"stats": {
        "total_scans": len(rows), "completed_scans": counts.get("completed", 0),
        "failed_scans": failed, "running_scans": active, "cancelled_scans": counts.get("cancelled", 0),
        "total_findings": len(all_findings), "highest_severity": highest_severity(all_findings),
        "severity_distribution": severity_distribution(all_findings), "recent_scans": recent,
    }})


@socketio.on("connect")
def socket_connect():
    user_id = session.get("user_id")
    if user_id:
        join_room(user_room(int(user_id)))
    emit("server_message", {"message": "connected"})


@socketio.on("join_scan")
def socket_join_scan(data):
    user_id = session.get("user_id")
    scan_id = (data or {}).get("scan_id")
    if not user_id or not scan_id or not get_user_scan(int(scan_id), int(user_id)):
        emit("server_message", {"message": "scan access denied"})
        return
    join_room(scan_room(int(scan_id)))
    emit("server_message", {"message": f"joined scan {scan_id}"})


def run_scan(
    scan_id: int,
    user_id: int,
    url: str,
    selected: list[str],
    payload_data: dict,
    runtime: ScanRuntime,
) -> None:
    results: list[dict] = []
    status = "done"
    error_message = ""
    selected_set = {scanner_key(item) for item in selected}
    scanners = [
        scanner for scanner in load_scanners()
        if scanner.__name__.split(".")[-1] in selected_set
    ]
    total = max(1, len(scanners))
    update_scan_progress(scan_id, status="running", progress=0, started=True)
    emit_log("Scan started", user_id, scan_id)

    try:
        with activate_runtime(runtime):
            for index, scanner in enumerate(scanners):
                if runtime.is_cancelled():
                    raise ScanCancelled("Scan cancellation was requested.")
                scanner_id = scanner.__name__.split(".")[-1]
                meta = getattr(scanner, "meta", {}) or {}
                display_name = meta.get("name", display_scanner_name(scanner_id))
                progress = int(index / total * 100)
                update_scan_progress(
                    scan_id, results=results, artifacts=runtime.artifacts, status="running", progress=progress,
                    current_scanner=display_name, request_count=runtime.request_count,
                )
                emit_log(f"Running {display_name}", user_id, scan_id)
                before = runtime.request_count
                try:
                    raw_result = scanner.scan(url, **scanner_kwargs(scanner, scanner_id, payload_data))
                    normalized = normalize_scanner_result(scanner_id, raw_result)
                except (ScanCancelled, RequestBudgetExceeded):
                    raise
                except Exception as exc:
                    normalized = normalize_scanner_result(
                        scanner_id,
                        {
                            "vulnerable": False,
                            "status": "error",
                            "result": f"Scanner error: {exc}",
                            "severity": "Info",
                            "confidence": "Low",
                        },
                    )
                normalized["requests_made"] = max(0, runtime.request_count - before)
                results.append(normalized)
                update_scan_progress(
                    scan_id, results=results, artifacts=runtime.artifacts, status="running",
                    progress=int((index + 1) / total * 100),
                    current_scanner=display_name, request_count=runtime.request_count,
                )
                emit_log(f"{display_name}: {normalized['status']} / {normalized['severity']}", user_id, scan_id)
            emit_log("Scan finished", user_id, scan_id)
    except ScanCancelled as exc:
        status = "cancelled"
        error_message = str(exc)
        emit_log("Scan cancelled", user_id, scan_id)
    except RequestBudgetExceeded as exc:
        status = "budget_exhausted"
        error_message = str(exc)
        emit_log(error_message, user_id, scan_id)
    except Exception as exc:
        status = "failed"
        error_message = f"Fatal scan error: {exc}"
        results.append(normalize_scanner_result("scan_engine", {"vulnerable": False, "status": "error", "result": error_message, "severity": "Info", "confidence": "High"}))
        emit_log(error_message, user_id, scan_id)
    finally:
        final_progress = 100 if status == "done" else min(99, int(len(results) / total * 100))
        payload = {"scan_id": scan_id, "status": status, "results": results, "progress": final_progress}
        try:
            audit(
                "scan.completed", user_id=user_id, target_type="scan", target_id=scan_id,
                details={"status": status, "request_count": runtime.request_count, "findings": len([r for r in results if is_finding(r)])},
                ip_address=str(payload_data.get("_audit_ip", "")),
            )
        except Exception:
            pass
        try:
            socketio.emit("scan_complete", payload, to=user_room(user_id))
            socketio.emit("scan_complete", payload, to=scan_room(scan_id))
        except Exception:
            pass
        # Persist the terminal state last. A client that observes a terminal
        # status can therefore rely on the worker having completed all side effects.
        update_scan_progress(
            scan_id, results=results, artifacts=runtime.artifacts, status=status, progress=final_progress,
            current_scanner="", request_count=runtime.request_count,
            error_message=error_message, completed=True,
        )


def active_scan_count(user_id: int) -> int:
    if not redis_backend_enabled():
        return active_count_for_user(user_id)
    conn = connect()
    row = conn.execute(
        "SELECT COUNT(*) AS total FROM scans WHERE user_id=? AND status IN ('queued','running','cancelling')",
        (user_id,),
    ).fetchone()
    conn.close()
    return int(row["total"] if row else 0)


@app.route("/scan-live", methods=["POST"])
def scan_live():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    data = request_payload()
    url = str(data.get("url", "")).strip()
    selected = data.get("vulns", [])
    if isinstance(selected, str):
        selected = [selected]
    if data.get("authorized") is not True:
        return jsonify({"error": "You must confirm that you own the target or have written authorization to test it."}), 400
    try:
        url = validate_target_url(url)
        hostname = (urlparse(url).hostname or "").lower()
        if not configured_host_allowed(hostname):
            raise ValueError("The target hostname is outside SCAN_ALLOWED_HOSTS.")
        if not target_in_user_scope(int(user_id), hostname):
            raise ValueError("The target hostname is outside your active authorized scope.")
        headers = sanitize_global_headers(data.get("http_headers"))
        cookies = parse_string_map(data.get("cookies"), label="Cookies")
        auth_profiles = parse_auth_profiles(data.get("auth_profiles"))
        browser_storage_state = parse_browser_storage_state(data.get("browser_storage_state"))
        request_budget = int(data.get("request_budget", DEFAULT_REQUEST_BUDGET))
        if not 10 <= request_budget <= MAX_REQUEST_BUDGET:
            raise ValueError(f"Request budget must be between 10 and {MAX_REQUEST_BUDGET}.")
        verify_tls = data.get("verify_tls", True) is not False
        if not verify_tls and not env_bool("ALLOW_INSECURE_TLS", False):
            raise ValueError("Disabling TLS verification is blocked by server policy.")
    except (UnsafeTargetError, AuthProfileError, ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    valid_ids = {item["id"] for item in load_scanner_specs()}
    selected = list(dict.fromkeys(scanner_key(item) for item in selected if scanner_key(item) in valid_ids))
    if not selected:
        return jsonify({"error": "Select at least one valid scanner."}), 400
    if active_scan_count(int(user_id)) >= MAX_ACTIVE_SCANS_PER_USER:
        return jsonify({"error": "Maximum concurrent scan limit reached."}), 429

    mode = str(data.get("scan_mode", "standard"))[:30]
    scan_id = create_scan_record(int(user_id), url, selected, scan_mode=mode, request_budget=request_budget)
    runtime_ephemeral = {
        "browser_storage_state": browser_storage_state,
        "auth_profiles": [profile.to_runtime_dict() for profile in auth_profiles],
    }
    safe_payload = dict(data)
    safe_payload.pop("http_headers", None)
    safe_payload.pop("cookies", None)
    safe_payload.pop("auth_profiles", None)
    safe_payload.pop("browser_storage_state", None)
    safe_payload["_audit_ip"] = client_ip()

    if redis_backend_enabled():
        try:
            queue = get_queue()
            queue.ping()
            queue.enqueue({
                "scan_id": scan_id,
                "user_id": int(user_id),
                "url": url,
                "selected": selected,
                "payload_data": safe_payload,
                "runtime": {
                    "request_budget": request_budget,
                    "default_headers": headers,
                    "cookies": cookies,
                    "verify_tls": verify_tls,
                    "allow_private": scanner_env_bool("ALLOW_PRIVATE_TARGETS", False),
                    "ephemeral": runtime_ephemeral,
                },
            })
        except Exception as exc:
            update_scan_progress(
                scan_id, status="failed", progress=0,
                error_message="Distributed queue unavailable or misconfigured.", completed=True,
            )
            return jsonify({"error": "The distributed scan queue is unavailable or misconfigured."}), 503
    else:
        runtime = ScanRuntime(
            scan_id=scan_id, user_id=int(user_id), request_budget=request_budget,
            default_headers=headers, cookies=cookies, verify_tls=verify_tls,
            allow_private=scanner_env_bool("ALLOW_PRIVATE_TARGETS", False),
            ephemeral=runtime_ephemeral,
        )
        register_scan_runtime(runtime)
        submit_scan_job(scan_id, run_scan, scan_id, int(user_id), url, selected, safe_payload, runtime)
    audit(
        "scan.started", user_id=int(user_id), target_type="scan", target_id=scan_id,
        details={"target": url, "scanners": selected, "request_budget": request_budget, "scan_mode": mode, "auth_profile_summaries": [profile.safe_summary() for profile in auth_profiles], "browser_storage_state": bool(browser_storage_state)},
        ip_address=client_ip(),
    )
    return jsonify({"message": "Scan queued", "scan_id": scan_id, "status": "queued"}), 202


@app.route("/scan-status/<int:scan_id>")
def scan_status(scan_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    row = get_user_scan(scan_id, int(user_id))
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"scan": serialize_scan_row(row)})


@app.route("/scan/<int:scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id: int):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    row = get_user_scan(scan_id, int(user_id))
    if not row:
        return jsonify({"error": "Not found"}), 404
    if row["status"] not in {"queued", "running", "cancelling"}:
        return jsonify({"error": f"Scan is already {row['status']}."}), 409
    managed = cancel_managed_scan(scan_id)
    distributed = False
    if redis_backend_enabled():
        try:
            get_queue().request_cancel(scan_id)
            distributed = True
        except Exception:
            distributed = False
    next_status = "cancelled" if row["status"] == "queued" else "cancelling"
    conn = connect()
    conn.execute(
        "UPDATE scans SET cancel_requested=1,status=?,completed_at=CASE WHEN ?='cancelled' THEN ? ELSE completed_at END WHERE id=? AND user_id=?",
        (next_status, next_status, utc_now(), scan_id, int(user_id)),
    )
    conn.commit(); conn.close()
    audit("scan.cancel_requested", user_id=int(user_id), target_type="scan", target_id=scan_id, details={"managed": managed, "distributed": distributed}, ip_address=client_ip())
    if request.is_json or request.accept_mimetypes.best == "application/json":
        return jsonify({"message": "Cancellation requested", "status": next_status})
    return redirect(f"/scan/{scan_id}")


@app.route("/oast/<token>", methods=["GET", "POST"])
def oast_callback(token: str):
    execution_token = request.args.get("execution", "")
    event = "script_fetch" if execution_token else "callback"
    recorded = record_hit(token, {"event": event})
    body = "/* CyberScan callback recorded */"
    if (
        recorded
        and execution_token
        and re.fullmatch(r"[A-Za-z0-9_-]{8,128}", execution_token)
        and is_registered(execution_token)
    ):
        encoded_token = json.dumps(execution_token)
        body = (
            "(function(){var s=document.currentScript;if(!s)return;"
            "var u=new URL(s.src);u.search='';u.hash='';"
            f"u.pathname=u.pathname.replace(/[^/]+$/, {encoded_token});"
            "var i=new Image();i.referrerPolicy='no-referrer';i.src=u.toString();})();"
        )
    response = app.response_class(body, mimetype="application/javascript")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response, 200 if recorded else 404


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "5.0.0",
        "queue_backend": "redis" if redis_backend_enabled() else "local",
        "workers": int(os.getenv("SCAN_WORKERS", "4")),
        "modern_features": ["playwright", "openapi", "graphql", "websocket", "grpc-reflection", "authorization-matrix", "oauth-oidc"],
    })


if __name__ == "__main__":
    socketio.run(app, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=env_bool("FLASK_DEBUG", False), allow_unsafe_werkzeug=env_bool("ALLOW_UNSAFE_WERKZEUG", True))
