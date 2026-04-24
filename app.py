from flask import Flask, render_template, request, jsonify, redirect, session
from flask_bcrypt import Bcrypt
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
import threading
import json
import inspect
from urllib.parse import urlparse

# -----------------------
# 🚀 App Setup
# -----------------------

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.secret_key = "secret123"

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

init_db()

# -----------------------
# 🛡️ Helpers
# -----------------------

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


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


def normalize_severity(value):
    if value is None:
        return "Low"

    text = str(value).strip().lower()

    if text in ("critical", "crit", "cr", "urgent"):
        return "Critical"
    if text in ("high", "hi", "h"):
        return "High"
    if text in ("medium", "med", "moderate", "mid"):
        return "Medium"
    return "Low"


def stronger_severity(current, candidate):
    current_rank = SEVERITY_ORDER.get(normalize_severity(current), 1)
    candidate_rank = SEVERITY_ORDER.get(normalize_severity(candidate), 1)
    return candidate if candidate_rank > current_rank else current


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
            raw_result.get("severity") or raw_result.get("risk") or "Low"
        )

        return {
            "name": scanner_name,
            "result": str(result_text),
            "severity": severity,
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
                    item.get("severity") or item.get("risk") or "Low"
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

    return render_template("history.html", scans=clean_scans)


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
                emit_log(f"[SCAN {scan_id}] [ERROR] {name}: {str(e)}")
                results.append(
                    {
                        "name": name,
                        "result": f"Error: {str(e)}",
                        "severity": "Low",
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
    socketio.run(app, debug=True)