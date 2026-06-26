from flask import Flask, render_template, request, jsonify, redirect, session, send_file
from flask_bcrypt import Bcrypt
from routes_ai import ai_bp
from database import init_db, connect
from main import load_scanners
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    verify_jwt_in_request,
    jwt_required,
)
from flask_socketio import SocketIO
from dotenv import load_dotenv
import threading
import json
import inspect
import os
import time
from io import BytesIO
from urllib.parse import urlparse
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

# -----------------------
# 🚀 App Setup
# -----------------------

load_dotenv()

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "change-this-jwt-secret")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-flask-secret")

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

init_db()
app.register_blueprint(ai_bp)

# -----------------------
# 🛡️ Helpers
# -----------------------

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}

DEFAULT_SEVERITY_BY_SCANNER = {
    "sql_injection": "High",
    "xss": "High",
    "stored_xss_scanner": "High",
    "blind_xss": "Medium",
    "ssrf": "High",
    "ssrf_scanner": "High",
    "idor": "High",
    "auth_scanner": "High",
    "weak_password_scanner": "High",
    "file_upload": "High",
    "path_traversal": "High",
    "cors_scanner": "Medium",
    "csrf_scan": "Medium",
    "clickjacking_scanner": "Low",
    "dir_scan": "Info",
    "info_scan": "Info",
}

NON_FINDING_PHRASES = (
    "no vulnerabilities found",
    "no information disclosure detected",
    "clickjacking protection detected",
    "cors configuration appears secure",
    "csrf protection header detected",
    "csrf token found in form",
    "no forms detected",
    "no directory listing detected",
    "rate limiting detected",
    "server delay detected",
)

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
    "ssrf": "A10: Server-Side Request Forgery",
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
}

RATE_LIMITS = {}
AUTH_RATE_LIMIT_WINDOW = int(os.getenv("AUTH_RATE_LIMIT_WINDOW", "300"))
AUTH_RATE_LIMIT_MAX = int(os.getenv("AUTH_RATE_LIMIT_MAX", "5"))


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def rate_limit_key(action, identifier):
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    client_ip = client_ip.split(",")[0].strip()
    return f"{action}:{client_ip}:{identifier or 'unknown'}"


def is_rate_limited(action, identifier):
    now = time.time()
    key = rate_limit_key(action, identifier)
    timestamps = RATE_LIMITS.get(key, [])
    timestamps = [ts for ts in timestamps if now - ts < AUTH_RATE_LIMIT_WINDOW]

    if len(timestamps) >= AUTH_RATE_LIMIT_MAX:
        RATE_LIMITS[key] = timestamps
        return True

    timestamps.append(now)
    RATE_LIMITS[key] = timestamps
    return False


def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False


def request_payload():
    """
    Supports both JSON API requests and HTML form submissions.
    """
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict()
    return data or {}


def scanner_key(name):
    return str(name or "unknown").strip().lower().replace("-", " ").replace(" ", "_")


def display_scanner_name(name):
    text = str(name or "Unknown Scanner").replace("_", " ").strip()
    return " ".join(part.capitalize() for part in text.split())


def default_severity_for_scanner(scanner_name):
    return DEFAULT_SEVERITY_BY_SCANNER.get(scanner_key(scanner_name), "Low")


def normalize_severity(value, scanner_name=None):
    if value is None or value == "":
        return default_severity_for_scanner(scanner_name)

    text = str(value).strip().lower()

    if text in ("critical", "crit", "cr", "urgent"):
        return "Critical"
    if text in ("high", "hi", "h"):
        return "High"
    if text in ("medium", "med", "moderate", "mid"):
        return "Medium"
    if text in ("info", "informational", "information"):
        return "Info"
    if text in ("low", "lo", "l"):
        return "Low"
    return default_severity_for_scanner(scanner_name)


def stronger_severity(current, candidate):
    current_rank = SEVERITY_ORDER.get(normalize_severity(current), 1)
    candidate_rank = SEVERITY_ORDER.get(normalize_severity(candidate), 1)
    return candidate if candidate_rank > current_rank else current


def owasp_category_for(scanner_name, text=""):
    key = scanner_key(scanner_name)
    if key in OWASP_BY_SCANNER:
        return OWASP_BY_SCANNER[key]

    haystack = f"{key} {text}".lower()
    if "sql" in haystack or "xss" in haystack or "injection" in haystack:
        return "A03: Injection"
    if "idor" in haystack or "traversal" in haystack or "redirect" in haystack:
        return "A01: Broken Access Control"
    if "ssrf" in haystack:
        return "A10: Server-Side Request Forgery"
    if "auth" in haystack or "password" in haystack or "rate" in haystack:
        return "A07: Identification and Authentication Failures"
    return "A05: Security Misconfiguration"


def recommendation_for(scanner_name, text=""):
    haystack = f"{scanner_key(scanner_name)} {text}".lower()

    if "sql" in haystack:
        return "Use parameterized queries, validate input, and avoid string-built SQL."
    if "stored_xss" in haystack or "xss" in haystack:
        return "Encode output, sanitize user input, and apply a strict Content Security Policy."
    if "idor" in haystack:
        return "Enforce object-level authorization before returning any resource."
    if "ssrf" in haystack:
        return "Validate outbound URLs, block internal IP ranges, and use an allowlist."
    if "csrf" in haystack:
        return "Add CSRF tokens to state-changing forms and validate them server-side."
    if "cors" in haystack:
        return "Restrict allowed origins and avoid wildcard CORS with credentials."
    if "clickjacking" in haystack:
        return "Set X-Frame-Options or CSP frame-ancestors to prevent iframe embedding."
    if "upload" in haystack:
        return "Validate file type, rename uploads, store outside web root, and scan files."
    if "path_traversal" in haystack or "traversal" in haystack:
        return "Normalize paths, restrict file access to an allowlisted directory, and block traversal patterns."
    if "weak_password" in haystack or "auth" in haystack or "rate_limit" in haystack:
        return "Use strong password policy, account lockout, MFA, and rate limiting."
    if "graphql" in haystack:
        return "Disable GraphQL introspection in production and enforce authorization."
    if "host_header" in haystack:
        return "Validate Host headers and configure trusted proxy settings."
    if "dir_scan" in haystack or "directory" in haystack:
        return "Disable directory listing and restrict access to sensitive folders."
    if "info" in haystack:
        return "Remove sensitive headers and avoid exposing stack traces or version details."
    return "Review the affected endpoint, validate input, and apply the recommended secure configuration."


def safe_json_loads(value):
    if value is None:
        return []
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        if not value.strip():
            return []
        try:
            return json.loads(value)
        except Exception:
            return [{"name": "raw_result", "result": value, "severity": "Info"}]
    return [{"name": "raw_result", "result": str(value), "severity": "Info"}]


def normalize_finding(raw_item, fallback_scanner="Unknown Scanner"):
    if isinstance(raw_item, dict):
        scanner_name = raw_item.get("name") or raw_item.get("scanner") or fallback_scanner
        description = (
            raw_item.get("result")
            or raw_item.get("message")
            or raw_item.get("status")
            or raw_item.get("description")
            or raw_item.get("details")
            or "No details available"
        )
        evidence = (
            raw_item.get("evidence")
            or raw_item.get("payload")
            or raw_item.get("url")
            or raw_item.get("endpoint")
            or ""
        )
        confidence = raw_item.get("confidence") or "Medium"
        severity = normalize_severity(raw_item.get("severity") or raw_item.get("risk"), scanner_name)
    else:
        scanner_name = fallback_scanner
        description = str(raw_item) if raw_item not in (None, "") else "No details available"
        evidence = ""
        confidence = "Low"
        severity = normalize_severity(None, scanner_name)

    text = str(description)

    return {
        "scanner": display_scanner_name(scanner_name),
        "scanner_key": scanner_key(scanner_name),
        "severity": severity,
        "description": text,
        "evidence": str(evidence) if evidence else "N/A",
        "recommendation": recommendation_for(scanner_name, text),
        "owasp": owasp_category_for(scanner_name, text),
        "confidence": str(confidence),
    }


def is_non_finding_result(raw_item):
    if not isinstance(raw_item, dict):
        return False

    text = str(
        raw_item.get("result")
        or raw_item.get("message")
        or raw_item.get("status")
        or raw_item.get("description")
        or raw_item.get("details")
        or ""
    ).lower()

    if "error:" in text or "could not complete" in text:
        return False

    if raw_item.get("vulnerable") is False:
        return True

    return any(phrase in text for phrase in NON_FINDING_PHRASES)


def normalize_scan_results(raw_results):
    parsed = safe_json_loads(raw_results)

    if isinstance(parsed, dict):
        parsed = [parsed]

    if not isinstance(parsed, list):
        parsed = [{"name": "raw_result", "result": str(parsed), "severity": "Info"}]

    findings = []
    for item in parsed:
        if is_non_finding_result(item):
            continue

        if isinstance(item, dict) and isinstance(item.get("details"), list) and not item.get("result"):
            for detail in item["details"]:
                if is_non_finding_result(detail):
                    continue
                findings.append(normalize_finding(detail, item.get("name", "Unknown Scanner")))
        else:
            findings.append(normalize_finding(item))

    return findings


def highest_severity(findings):
    if not findings:
        return "Info"
    return max((f["severity"] for f in findings), key=lambda sev: SEVERITY_ORDER.get(sev, 0))


def severity_distribution(findings):
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        severity = normalize_severity(finding.get("severity"), finding.get("scanner"))
        distribution[severity] = distribution.get(severity, 0) + 1
    return distribution


def scan_status_bucket(status):
    value = str(status or "done").lower()
    if value in ("done", "complete", "completed"):
        return "completed"
    if value == "running":
        return "running"
    if value == "failed":
        return "failed"
    return value


def group_findings_by_scanner(findings):
    groups = {}
    for finding in findings:
        groups.setdefault(finding["scanner"], []).append(finding)
    return [{"scanner": scanner, "findings": items} for scanner, items in groups.items()]


def build_scan_export_payload(row):
    findings = normalize_scan_results(row["result"])
    distribution = severity_distribution(findings)
    return {
        "scan_id": row["id"],
        "target": row["target"],
        "status": row["status"] or "done",
        "created_at": row["created_at"],
        "total_findings": len(findings),
        "highest_severity": highest_severity(findings),
        "severity_distribution": distribution,
        "normalized_findings": findings,
        "owasp_categories": sorted({f.get("owasp", "N/A") for f in findings if f.get("owasp")}),
        "recommendations": sorted(
            {f.get("recommendation", "N/A") for f in findings if f.get("recommendation")}
        ),
    }


def get_user_scan(scan_id, user_id):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT scans.id, scans.target, scans.result, scans.status, scans.created_at,
               users.email
        FROM scans
        JOIN users ON users.id = scans.user_id
        WHERE scans.id=? AND scans.user_id=?
        """,
        (scan_id, user_id),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def pdf_paragraph(value, style):
    return Paragraph(escape(str(value if value is not None else "N/A")), style)


def build_scan_report_pdf(scan):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="SmallMuted",
            parent=styles["BodyText"],
            fontSize=8,
            textColor=colors.HexColor("#64748B"),
            leading=11,
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Heading3"],
            fontSize=11,
            leading=14,
            spaceAfter=6,
        )
    )

    elements = []
    elements.append(pdf_paragraph("CyberScan Security Report", styles["Title"]))
    elements.append(pdf_paragraph("Generated for authorized security testing and educational purposes only.", styles["SmallMuted"]))
    elements.append(Spacer(1, 14))

    summary_data = [
        [pdf_paragraph("Target URL", styles["BodyText"]), pdf_paragraph(scan["target"], styles["BodyText"])],
        [pdf_paragraph("Scan Date", styles["BodyText"]), pdf_paragraph(scan["created_at"], styles["BodyText"])],
        [pdf_paragraph("Scan Status", styles["BodyText"]), pdf_paragraph(scan["status"], styles["BodyText"])],
        [pdf_paragraph("Total Findings", styles["BodyText"]), pdf_paragraph(scan["findings_count"], styles["BodyText"])],
        [pdf_paragraph("Highest Severity", styles["BodyText"]), pdf_paragraph(scan["highest_severity"], styles["BodyText"])],
    ]
    summary = Table(summary_data, colWidths=[120, 360])
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E2E8F0")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(summary)
    elements.append(Spacer(1, 16))

    if not scan["groups"]:
        elements.append(pdf_paragraph("No findings were detected or saved for this scan.", styles["Heading2"]))
    else:
        elements.append(pdf_paragraph("Findings", styles["Heading2"]))
        elements.append(Spacer(1, 8))

        for group in scan["groups"]:
            elements.append(pdf_paragraph(group["scanner"], styles["Heading3"]))

            for finding in group["findings"]:
                elements.append(pdf_paragraph(f'{finding["scanner"]} - {finding["severity"]}', styles["FindingTitle"]))
                finding_data = [
                    [pdf_paragraph("OWASP", styles["BodyText"]), pdf_paragraph(finding["owasp"], styles["BodyText"])],
                    [pdf_paragraph("Description", styles["BodyText"]), pdf_paragraph(finding["description"], styles["BodyText"])],
                    [pdf_paragraph("Evidence", styles["BodyText"]), pdf_paragraph(finding["evidence"], styles["BodyText"])],
                    [pdf_paragraph("Recommendation", styles["BodyText"]), pdf_paragraph(finding["recommendation"], styles["BodyText"])],
                    [pdf_paragraph("Confidence", styles["BodyText"]), pdf_paragraph(finding["confidence"], styles["BodyText"])],
                ]
                finding_table = Table(finding_data, colWidths=[100, 380])
                finding_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                            ("TOPPADDING", (0, 0), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                elements.append(finding_table)
                elements.append(Spacer(1, 10))

    elements.append(Spacer(1, 14))
    elements.append(pdf_paragraph("Disclaimer", styles["Heading2"]))
    elements.append(
        pdf_paragraph(
            "This report is generated for authorized security testing and educational purposes only.",
            styles["BodyText"],
        )
    )

    doc.build(elements)
    buffer.seek(0)
    return buffer


def normalize_scanner_result(scanner_name, raw_result):
    """
    Accepts scanner outputs in multiple formats:
    - dict
    - list
    - string
    - None
    """
    if isinstance(raw_result, dict):
        result_text = (
            raw_result.get("result")
            or raw_result.get("message")
            or raw_result.get("status")
            or raw_result.get("details")
        )
        if result_text is None:
            result_text = json.dumps(raw_result, ensure_ascii=False)

        severity = normalize_severity(
            raw_result.get("severity") or raw_result.get("risk"), scanner_name
        )

        return {
            "name": scanner_name,
            "result": str(result_text),
            "severity": severity,
            "vulnerable": raw_result.get("vulnerable"),
        }

    if isinstance(raw_result, list):
        if not raw_result:
            return {
                "name": scanner_name,
                "result": "No vulnerabilities found",
                "severity": "Low",
            }

        texts = []
        severity = "Low"

        for item in raw_result:
            if isinstance(item, dict):
                item_text = (
                    item.get("result")
                    or item.get("status")
                    or item.get("type")
                    or item.get("payload")
                    or json.dumps(item, ensure_ascii=False)
                )
                item_severity = normalize_severity(
                    item.get("severity") or item.get("risk"), scanner_name
                )
                severity = stronger_severity(severity, item_severity)
                texts.append(str(item_text))
            else:
                texts.append(str(item))

        return {
            "name": scanner_name,
            "result": " | ".join(texts),
            "severity": severity,
        }

    if raw_result is None or raw_result == "":
        return {
            "name": scanner_name,
            "result": "No vulnerabilities found",
            "severity": "Low",
        }

    text = str(raw_result)

    # Basic heuristics for old scanners returning raw strings
    severity = "Low"
    lowered = text.lower()
    if "critical" in lowered:
        severity = "Critical"
    elif "high" in lowered:
        severity = "High"
    elif "medium" in lowered:
        severity = "Medium"

    return {
        "name": scanner_name,
        "result": text,
        "severity": severity,
    }


def get_current_user_id():
    """
    Works with either:
    - session-based login
    - JWT-based API login
    """
    if "user_id" in session:
        return session["user_id"]

    try:
        verify_jwt_in_request(optional=True)
        return get_jwt_identity()
    except Exception:
        return None


def load_scanner_specs():
    """
    Used by /api/scanners to expose scanner names and required inputs.
    """
    specs = []
    scanners = load_scanners()

    for scanner in scanners:
        name = scanner.__name__.split(".")[-1]
        specs.append(
            {
                "name": name,
                "inputs": getattr(scanner, "inputs", []),
                "meta": getattr(scanner, "meta", {}),
            }
        )

    return specs


def build_scanner_args(scanner, scanner_name, url, payload_data):
    """
    Builds positional args for scanner.scan(url, ...)
    Supports scanners with 1, 2, or 3+ args after url.
    """
    signature = inspect.signature(scanner.scan)
    params = list(signature.parameters.values())[1:]  # skip url

    args = [url]

    for param in params:
        key_candidates = [
            f"{scanner_name}_{param.name}",
            param.name,
            f"{scanner_name}_param",
            f"{scanner_name}_{param.name.replace('-', '_')}",
        ]

        value = None
        for key in key_candidates:
            if key in payload_data and payload_data.get(key) not in (None, ""):
                value = payload_data.get(key)
                break

        if value is None and param.default is not inspect._empty:
            value = param.default

        if value is None:
            value = "test"

        args.append(value)

    return args


def create_scan_record(user_id, url):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO scans (user_id, target, result, status) VALUES (?, ?, ?, ?)",
        (user_id, url, json.dumps([]), "running"),
    )

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan_record(scan_id, results, status="done"):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE scans SET result=?, status=? WHERE id=?",
        (json.dumps(results), status, scan_id),
    )

    conn.commit()
    conn.close()


def emit_log(message):
    socketio.emit("log", message)


def normalize_selected_scanners(selected):
    normalized = []
    for item in selected or []:
        name = str(item).strip().lower().replace("-", " ").replace(" ", "_")
        if name:
            normalized.append(name)
    return normalized


# -----------------------
# 🏠 Web Pages
# -----------------------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if is_rate_limited("register", email):
            return "Too many registration attempts. Please try again later.", 429

        if not email or not password:
            return "Email and password are required"

        if password != confirm:
            return "Passwords do not match"

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        if cursor.fetchone():
            conn.close()
            return "Email already exists"

        cursor.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, hashed_password),
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if is_rate_limited("login", email):
            return "Too many login attempts. Please try again later.", 429

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect("/dashboard")

        return "Invalid email or password"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html")


@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, target, result, status, created_at
        FROM scans
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    rows = cursor.fetchall()
    conn.close()

    clean_scans = []

    for row in rows:
        findings = normalize_scan_results(row["result"])

        clean_scans.append(
            {
                "id": row["id"],
                "target": row["target"],
                "results": findings,
                "findings_count": len(findings),
                "highest_severity": highest_severity(findings),
                "status": row["status"],
                "created_at": row["created_at"],
            }
        )

    return render_template("history.html", scans=clean_scans)


@app.route("/scan/<int:scan_id>")
def scan_details(scan_id):
    if "user_id" not in session:
        return redirect("/login")

    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404

    findings = normalize_scan_results(row["result"])
    scan = {
        "id": row["id"],
        "target": row["target"],
        "status": row["status"] or "done",
        "created_at": row["created_at"],
        "email": row["email"],
        "findings_count": len(findings),
        "highest_severity": highest_severity(findings),
        "groups": group_findings_by_scanner(findings),
    }

    return render_template("scan_details.html", scan=scan)


@app.route("/scan/<int:scan_id>/report")
def scan_report(scan_id):
    if "user_id" not in session:
        return redirect("/login")

    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404

    findings = normalize_scan_results(row["result"])
    scan = {
        "id": row["id"],
        "target": row["target"],
        "status": row["status"] or "done",
        "created_at": row["created_at"],
        "email": row["email"],
        "findings_count": len(findings),
        "highest_severity": highest_severity(findings),
        "groups": group_findings_by_scanner(findings),
    }

    pdf_buffer = build_scan_report_pdf(scan)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"cyberscan-scan-{scan_id}-report.pdf",
    )


@app.route("/scan/<int:scan_id>/export-json")
def scan_export_json(scan_id):
    if "user_id" not in session:
        return redirect("/login")

    row = get_user_scan(scan_id, session["user_id"])
    if not row:
        return "Scan not found", 404

    payload = build_scan_export_payload(row)
    json_buffer = BytesIO(json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"))

    return send_file(
        json_buffer,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"cyberscan-scan-{scan_id}-results.json",
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -----------------------
# 🔐 JWT API
# -----------------------

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request_payload()

    email = data.get("email", "").strip()
    password = data.get("password", "")

    if is_rate_limited("api_register", email):
        return jsonify({"error": "Too many registration attempts. Please try again later."}), 429

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "User exists"}), 400

    cursor.execute(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        (email, hashed_password),
    )
    conn.commit()
    conn.close()

    return jsonify({"msg": "Registered successfully"}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request_payload()

    email = data.get("email", "").strip()
    password = data.get("password", "")

    if is_rate_limited("api_login", email):
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = connect()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user["password"], password):
        token = create_access_token(identity=user["id"])
        return jsonify(
            {
                "token": token,
                "user_id": user["id"],
                "email": user["email"],
            }
        )

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/scanners", methods=["GET"])
def api_scanners():
    return jsonify({"scanners": load_scanner_specs()})


@app.route("/api/history", methods=["GET"])
@jwt_required(optional=True)
def api_history():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, target, result, status, created_at
        FROM scans
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    rows = cursor.fetchall()
    conn.close()

    clean_scans = []

    for row in rows:
        try:
            parsed_results = json.loads(row["result"])
            if not isinstance(parsed_results, list):
                parsed_results = []
        except Exception:
            parsed_results = []

        clean_scans.append(
            {
                "id": row["id"],
                "target": row["target"],
                "results": parsed_results,
                "status": row["status"],
                "created_at": row["created_at"],
            }
        )

    return jsonify({"scans": clean_scans})


@app.route("/api/dashboard-stats", methods=["GET"])
@jwt_required(optional=True)
def api_dashboard_stats():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, target, result, status, created_at
        FROM scans
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (user_id,),
    )

    rows = cursor.fetchall()
    conn.close()

    all_findings = []
    recent_scans = []
    completed_scans = 0
    failed_scans = 0
    running_scans = 0

    for row in rows:
        findings = normalize_scan_results(row["result"])
        all_findings.extend(findings)

        status = scan_status_bucket(row["status"])
        if status == "completed":
            completed_scans += 1
        elif status == "failed":
            failed_scans += 1
        elif status == "running":
            running_scans += 1

        if len(recent_scans) < 5:
            recent_scans.append(
                {
                    "id": row["id"],
                    "target": row["target"],
                    "status": status,
                    "created_at": row["created_at"],
                    "findings_count": len(findings),
                    "highest_severity": highest_severity(findings),
                }
            )

    stats = {
        "total_scans": len(rows),
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "running_scans": running_scans,
        "total_findings": len(all_findings),
        "highest_severity": highest_severity(all_findings),
        "severity_distribution": severity_distribution(all_findings),
        "recent_scans": recent_scans,
    }

    return jsonify({"stats": stats})


# -----------------------
# 📡 Socket Events
# -----------------------

@socketio.on("connect")
def handle_connect():
    socketio.emit("server_message", {"message": "connected"})


@socketio.on("disconnect")
def handle_disconnect():
    pass


@socketio.on("join_scan")
def handle_join_scan(data):
    """
    Optional room joining for future dashboard JS.
    """
    try:
        scan_id = data.get("scan_id")
        if scan_id:
            socketio.emit(
                "server_message",
                {"message": f"joined scan {scan_id}"},
            )
    except Exception:
        pass


# -----------------------
# ⚡ Async Scan Engine
# -----------------------

def run_scan(scan_id, user_id, url, selected, payload_data):
    scanners = load_scanners()
    selected = set(normalize_selected_scanners(selected))
    results = []
    status = "done"

    try:
        emit_log(f"[SCAN {scan_id}] [+] Starting scan...")

        for scanner in scanners:
            name = scanner.__name__.split(".")[-1]

            if selected and name not in selected:
                continue

            try:
                emit_log(f"[SCAN {scan_id}] [+] Testing {name}...")

                args = build_scanner_args(scanner, name, url, payload_data)
                raw_result = scanner.scan(*args)

                normalized = normalize_scanner_result(name, raw_result)
                results.append(normalized)

                emit_log(f"[SCAN {scan_id}] [RESULT] {name}: {normalized['result']}")

            except Exception as e:
                friendly_error = (
                    f"{display_scanner_name(name)} could not complete. "
                    f"Reason: {str(e)}"
                )
                emit_log(f"[SCAN {scan_id}] [ERROR] {friendly_error}")
                results.append(
                    {
                        "name": name,
                        "result": friendly_error,
                        "severity": "Info",
                        "confidence": "Low",
                    }
                )

        emit_log(f"[SCAN {scan_id}] [✔] Scan Finished")

    except Exception as e:
        status = "failed"
        emit_log(f"[SCAN {scan_id}] [FATAL] {str(e)}")

    finally:
        try:
            update_scan_record(scan_id, results, status=status)
        except Exception as e:
            emit_log(f"[SCAN {scan_id}] [DB ERROR] {str(e)}")

        socketio.emit(
            "scan_complete",
            {
                "scan_id": scan_id,
                "user_id": user_id,
                "status": status,
                "results": results,
            },
        )
# -----------------------
# 📡 Scan API
# -----------------------

@app.route("/scan-live", methods=["POST"])
def scan_live():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request_payload()
    url = data.get("url", "").strip()
    selected = data.get("vulns", [])

    if isinstance(selected, str):
        selected = [selected]

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    # Keep scan data for dynamic inputs and scanner args
    payload_data = dict(data)

    scan_id = create_scan_record(user_id, url)

    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, user_id, url, selected, payload_data),
        daemon=True,
    )
    thread.start()

    return jsonify(
        {
            "msg": "Scan started",
            "scan_id": scan_id,
        }
    )


@app.route("/scan-status/<int:scan_id>", methods=["GET"])
def scan_status(scan_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = connect()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id, target, result, status, created_at FROM scans WHERE id=? AND user_id=?",
        (scan_id, session["user_id"]),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Not found"}), 404

    try:
        parsed_results = json.loads(row["result"])
        if not isinstance(parsed_results, list):
            parsed_results = []
    except Exception:
        parsed_results = []

    return jsonify(
        {
            "scan": {
                "id": row["id"],
                "target": row["target"],
                "results": parsed_results,
                "status": row["status"],
                "created_at": row["created_at"],
            }
        }
    )


# -----------------------
# ▶️ Run
# -----------------------

if __name__ == "__main__":
    socketio.run(app, debug=env_bool("FLASK_DEBUG", False))
