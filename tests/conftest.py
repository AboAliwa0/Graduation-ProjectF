import os
import socket
import sys
import threading
from pathlib import Path

import pytest
from flask import Flask, Response, jsonify, redirect, request
from markupsafe import escape
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
os.environ["OAST_ALLOW_PRIVATE_CALLBACKS"] = "true"
os.environ["SCANNER_TIMEOUT"] = "3"

from services.oast import record_hit  # noqa: E402


@pytest.fixture(scope="session")
def lab_server():
    app = Flask(__name__)
    uploaded = {}
    stored = {"raw": [], "safe": []}
    counters = {"auth_safe": 0, "auth_429": 0, "auth_retry": 0, "rate_safe": 0, "rate_delay": 0}

    @app.after_request
    def lab_headers(response):
        response.headers["X-Lab"] = "CyberScan-Test-Lab"
        return response

    @app.route("/safe/headers")
    def safe_headers():
        response = Response("safe page", mimetype="text/html")
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response

    @app.route("/safe/csp-self")
    def safe_csp_self():
        response = Response("safe CSP page", mimetype="text/html")
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'self'"
        return response

    @app.route("/vuln/csp-wildcard")
    def vulnerable_csp_wildcard():
        response = Response("frame me", mimetype="text/html")
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors *"
        return response

    @app.route("/api/json")
    def json_api():
        return jsonify({"status": "ok"})

    @app.route("/vuln/clickjacking")
    def vuln_clickjacking():
        return Response("frame me", mimetype="text/html")

    @app.route("/vuln/cors", methods=["GET", "OPTIONS"])
    def vuln_cors():
        origin = request.headers.get("Origin", "")
        response = Response("private data", mimetype="text/plain")
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Vary"] = "Origin"
        return response

    @app.route("/potential/cors", methods=["GET", "OPTIONS"])
    def potential_cors():
        origin = request.headers.get("Origin", "")
        response = Response("public documentation", mimetype="text/plain")
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        return response

    @app.route("/info/cors-wildcard", methods=["GET", "OPTIONS"])
    def informational_cors_wildcard():
        response = Response("public data", mimetype="text/plain")
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    @app.route("/safe/cors-failed-preflight", methods=["GET", "OPTIONS"])
    def failed_cors_preflight():
        if request.method == "OPTIONS":
            response = Response("forbidden", status=403, mimetype="text/plain")
            response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
            return response
        return Response("public data", mimetype="text/plain")

    @app.route("/safe/cors", methods=["GET", "OPTIONS"])
    def safe_cors():
        response = Response("public data", mimetype="text/plain")
        response.headers["Access-Control-Allow-Origin"] = "https://trusted.example"
        return response

    @app.route("/vuln/csrf")
    def vuln_csrf():
        return Response('<form method="post" action="/change"><input name="email"></form>', mimetype="text/html")

    @app.route("/safe/csrf")
    def safe_csrf():
        return Response('<form method="get"><input name="q"></form><form method="post"><input type="hidden" name="csrf_token" value="x"><input name="email"></form>', mimetype="text/html")

    @app.route("/lab/uploads/")
    def directory_listing():
        return Response('<title>Index of /uploads</title><h1>Index of /uploads</h1><a href="a.txt">a</a><a href="b.txt">b</a>', mimetype="text/html")

    @app.route("/lab-safe/uploads/")
    def no_directory_listing():
        return Response("not found", status=404, mimetype="text/plain")

    @app.route("/lab-custom/uploads/")
    def custom_directory_page():
        return Response('<title>Uploads</title><a href="a.txt">a</a><a href="b.txt">b</a>', mimetype="text/html")

    @app.route("/vuln/info")
    def vuln_info():
        return Response("Traceback (most recent call last):\n  File app.py\nValueError", mimetype="text/plain")

    @app.route("/vuln/graphql", methods=["POST"])
    def vuln_graphql():
        return jsonify({"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None}}})

    @app.route("/safe/graphql", methods=["POST"])
    def safe_graphql():
        return jsonify({"data": None, "errors": [{"message": "Introspection is disabled"}]})

    @app.route("/vuln/redirect")
    def vuln_redirect():
        return redirect(request.args.get("next", "/"), 302)

    @app.route("/safe/redirect")
    def safe_redirect():
        return redirect("/safe/headers", 302)

    @app.route("/vuln/host")
    def vuln_host():
        return Response(f"reset link: https://{request.host}/reset", mimetype="text/html")

    @app.route("/vuln/host-redirect")
    def vuln_host_redirect():
        return redirect(f"https://{request.host}/reset", 302)

    @app.route("/safe/host")
    def safe_host():
        return Response("reset link: https://trusted.example/reset", mimetype="text/html")

    @app.route("/vuln/html")
    def vuln_html():
        return Response(f"<main>{request.args.get('q', '')}</main>", mimetype="text/html")

    @app.route("/safe/html")
    def safe_html():
        return Response(f"<main>{escape(request.args.get('q', ''))}</main>", mimetype="text/html")

    @app.route("/safe/textarea")
    def safe_textarea_context():
        return Response(f"<textarea>{escape(request.args.get('q', ''))}</textarea>", mimetype="text/html")

    @app.route("/safe/title")
    def safe_title_context():
        return Response(f"<title>{escape(request.args.get('q', ''))}</title>", mimetype="text/html")

    @app.route("/vuln/sqli")
    def vuln_sqli():
        value = request.args.get("id", "")
        if value in {"'", '"', "')"}:
            return Response("You have an error in your SQL syntax", status=500, mimetype="text/plain")
        if "1=2" in value:
            return Response("record not found", status=404, mimetype="text/plain")
        return Response("record id=1 owner=authorized-user active=true", mimetype="text/plain")

    @app.route("/safe/dynamic")
    def safe_dynamic():
        token = request.args.get("id", "")
        return Response(f"normal response for value={escape(token)} request=0123456789abcdef0123456789abcdef", mimetype="text/html")

    @app.route("/vuln/traversal")
    def vuln_traversal():
        if request.args.get("file") == "../private/cyberscan-canary.txt":
            return Response("CYBERSCAN_CANARY", mimetype="text/plain")
        return Response("not found", status=404, mimetype="text/plain")

    @app.route("/safe/traversal")
    def safe_traversal():
        return Response("not found", status=404, mimetype="text/plain")

    @app.route("/vuln/upload", methods=["POST"])
    def vuln_upload():
        item = request.files.get("file")
        if not item:
            return jsonify({"error": "missing"}), 400
        uploaded[item.filename] = (item.read(), item.mimetype)
        return jsonify({"url": f"/public/{item.filename}"})

    @app.route("/safe/upload", methods=["POST"])
    def safe_upload():
        item = request.files.get("file")
        if not item:
            return jsonify({"error": "missing"}), 400
        uploaded["safe-" + item.filename] = (item.read(), "text/plain")
        return jsonify({"accepted": True})

    @app.route("/upload/cross-origin", methods=["POST"])
    def cross_origin_upload():
        item = request.files.get("file")
        if not item:
            return jsonify({"error": "missing"}), 400
        item.read()
        return jsonify({"url": f"https://unrelated.example/uploads/{item.filename}"})

    @app.route("/public/<path:name>")
    def public_file(name):
        data, content_type = uploaded.get(name, (b"missing", "text/plain"))
        return Response(data, status=200 if name in uploaded else 404, content_type=content_type)

    @app.route("/safe-public/<path:name>")
    def safe_public_file(name):
        data, _ = uploaded.get("safe-" + name, (b"missing", "text/plain"))
        response = Response(data, status=200 if "safe-" + name in uploaded else 404, content_type="text/plain")
        response.headers["Content-Disposition"] = "attachment"
        return response

    @app.route("/vuln/idor")
    def vuln_idor():
        object_id = request.args.get("id")
        return jsonify({"id": object_id, "account_owner": "private_marker", "balance": 1000})

    @app.route("/safe/idor")
    def safe_idor():
        if request.args.get("id") != "1001":
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"id": "1001", "account_owner": "private_marker", "balance": 1000})

    @app.route("/potential/idor")
    def potential_idor():
        return jsonify({
            "id": request.args.get("id"),
            "summary": "read-only authorization comparison response " * 4,
        })

    @app.route("/vuln/login", methods=["POST"])
    def vuln_login():
        if request.form.get("username") == "test-user" and request.form.get("password") == "Password1":
            return Response("Welcome test-user", mimetype="text/plain")
        return Response("Invalid credentials", status=401, mimetype="text/plain")

    @app.route("/safe/login", methods=["POST"])
    def safe_login():
        return Response("Invalid credentials", status=401, mimetype="text/plain")

    @app.route("/login/marker-401", methods=["POST"])
    def login_marker_401():
        return Response("Welcome text in a rejected response", status=401, mimetype="text/plain")

    @app.route("/login/redirect", methods=["POST"])
    def login_redirect():
        return redirect("/dashboard?token=fixture-secret", code=302)

    @app.route("/vuln/auth", methods=["POST"])
    def vuln_auth():
        return Response("Invalid credentials", status=401, mimetype="text/plain")

    @app.route("/safe/auth", methods=["POST"])
    def safe_auth():
        counters["auth_safe"] += 1
        if counters["auth_safe"] >= 3:
            response = Response("Too many attempts", status=429, mimetype="text/plain")
            response.headers["Retry-After"] = "60"
            return response
        return Response("Invalid credentials", status=401, mimetype="text/plain")

    @app.route("/auth/no-protection", methods=["POST"])
    def auth_no_protection():
        return Response("Invalid credentials", status=401, mimetype="text/plain")

    @app.route("/auth/http-429", methods=["POST"])
    def auth_http_429():
        counters["auth_429"] += 1
        if counters["auth_429"] >= 3:
            return Response("Invalid credentials: too many requests", status=429, mimetype="text/plain")
        return Response("Invalid credentials", status=401, mimetype="text/plain")

    @app.route("/auth/retry-after", methods=["POST"])
    def auth_retry_after():
        counters["auth_retry"] += 1
        response = Response("Invalid credentials", status=401, mimetype="text/plain")
        if counters["auth_retry"] >= 2:
            response.headers["Retry-After"] = "60"
        return response

    @app.route("/auth/captcha", methods=["POST"])
    def auth_captcha():
        return Response("Invalid credentials. CAPTCHA required.", status=401, mimetype="text/plain")

    @app.route("/auth/lockout", methods=["POST"])
    def auth_lockout():
        return Response("Invalid credentials. Account locked.", status=403, mimetype="text/plain")

    @app.route("/auth/rate-marker", methods=["POST"])
    def auth_rate_marker():
        return Response("Invalid credentials. Slow down.", status=401, mimetype="text/plain")

    @app.route("/auth/unreliable", methods=["POST"])
    def auth_unreliable():
        return Response("Unexpected login response", status=200, mimetype="text/plain")

    @app.route("/vuln/rate")
    def vuln_rate():
        return Response("ok", mimetype="text/plain")

    @app.route("/safe/rate")
    def safe_rate():
        counters["rate_safe"] += 1
        if counters["rate_safe"] >= 3:
            response = Response("Too many requests", status=429, mimetype="text/plain")
            response.headers["Retry-After"] = "60"
            return response
        return Response("ok", mimetype="text/plain")

    @app.route("/safe/rate-delay")
    def safe_rate_delay():
        import time
        counters["rate_delay"] += 1
        time.sleep(counters["rate_delay"] * 0.12)
        return Response("ok", mimetype="text/plain")

    @app.route("/vuln/stored", methods=["POST"])
    def vuln_stored_submit():
        stored["raw"].append(request.form.get("comment", ""))
        return Response("saved", mimetype="text/plain")

    @app.route("/vuln/stored-view")
    def vuln_stored_view():
        return Response("<html>" + "".join(stored["raw"]) + "</html>", mimetype="text/html")

    @app.route("/safe/stored", methods=["POST"])
    def safe_stored_submit():
        stored["safe"].append(request.form.get("comment", ""))
        return Response("saved", mimetype="text/plain")

    @app.route("/safe/stored-view")
    def safe_stored_view():
        return Response("<html>" + "".join(str(escape(v)) for v in stored["safe"]) + "</html>", mimetype="text/html")

    @app.route("/stored/fail-submit", methods=["POST"])
    def stored_fail_submit():
        return Response("submission failed", status=500, mimetype="text/plain")

    @app.route("/stored/fail-view")
    def stored_fail_view():
        return Response("view failed", status=500, mimetype="text/html")

    @app.route("/vuln/ssrf")
    def vuln_ssrf():
        import requests
        destination = request.args.get("url", "")
        if destination:
            requests.get(destination, timeout=2)
        return Response("processed", mimetype="text/plain")

    @app.route("/safe/ssrf")
    def safe_ssrf():
        return Response("URL accepted without a server-side request", mimetype="text/plain")

    @app.route("/vuln/blind-xss")
    def vuln_blind_xss():
        import re
        import requests
        value = request.args.get("message", "")
        match = re.search(r'<script\s+src="([^"]+)"', value, flags=re.I)
        if match:
            requests.get(match.group(1), timeout=2)
        return Response("stored", mimetype="text/plain")

    @app.route("/vuln/blind-xss-execute")
    def vuln_blind_xss_execute():
        import re
        from urllib.parse import parse_qs, urlparse

        import requests

        value = request.args.get("message", "")
        match = re.search(r'<script\s+src="([^"]+)"', value, flags=re.I)
        if match:
            script_url = match.group(1)
            requests.get(script_url, timeout=2)
            parsed = urlparse(script_url)
            execution_token = parse_qs(parsed.query).get("execution", [""])[0]
            if execution_token:
                requests.get(f"{parsed.scheme}://{parsed.netloc}/oast/{execution_token}", timeout=2)
        return Response("rendered in isolated browser fixture", mimetype="text/plain")

    @app.route("/safe/blind-xss")
    def safe_blind_xss():
        return Response("stored as inert text", mimetype="text/plain")

    @app.route("/echo-auth")
    def echo_auth():
        return jsonify({
            "authorization": request.headers.get("Authorization", ""),
            "cookie": request.headers.get("Cookie", ""),
            "custom": request.headers.get("X-Test-Header", ""),
        })


    @app.route("/modern/")
    def modern_spa():
        return Response(
            """<!doctype html><html><head><title>Modern Lab</title></head>
            <body><div id='root' data-reactroot>Modern application</div>
            <a href='/modern/settings'>Settings</a>
            <form action='/modern/search' method='get'><input name='q'></form>
            <script>fetch('/modern/api/profile').then(r=>r.json()).then(x=>document.body.dataset.loaded=x.role);</script>
            </body></html>""",
            mimetype="text/html",
        )

    @app.route("/modern/settings")
    def modern_settings():
        return Response("<html><body><h1>Settings</h1><script>fetch('/modern/api/settings')</script></body></html>", mimetype="text/html")

    @app.route("/modern/api/profile")
    def modern_profile():
        return jsonify({"id": 1001, "role": "user"})

    @app.route("/modern/api/settings")
    def modern_api_settings():
        return jsonify({"theme": "dark"})

    @app.route("/openapi.json")
    def openapi_document():
        return jsonify({
            "openapi": "3.1.0",
            "info": {"title": "CyberScan Modern Lab", "version": "1.0.0"},
            "servers": [{"url": "/"}],
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearerAuth": []}],
            "paths": {
                "/modern/api/profile": {"get": {"operationId": "getProfile", "responses": {"200": {"description": "ok"}}}},
                "/admin/data": {"get": {"operationId": "adminData", "security": [], "responses": {"200": {"description": "ok"}}}},
            },
        })

    @app.route("/openapi32.json")
    def openapi_32_document():
        return jsonify({
            "openapi": "3.2.0",
            "info": {"title": "CyberScan OpenAPI 3.2 Lab", "version": "1.0.0"},
            "servers": [{"url": "/"}],
            "paths": {
                "/modern/api/profile": {
                    "get": {"operationId": "getProfile32", "responses": {"200": {"description": "ok"}}}
                }
            },
        })

    @app.route("/admin/data")
    def admin_data():
        return jsonify({"admin": True, "secret": "lab-only"})

    @app.route("/graphql-modern", methods=["POST"])
    def graphql_modern():
        return jsonify({"data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [{"name": "viewer", "isDeprecated": False, "args": [], "type": {"kind": "OBJECT", "name": "User", "ofType": None}}]},
                {"kind": "OBJECT", "name": "Mutation", "fields": [{"name": "updateProfile", "isDeprecated": False, "args": [{"name": "name", "type": {"kind": "SCALAR", "name": "String", "ofType": None}}], "type": {"kind": "OBJECT", "name": "User", "ofType": None}}]},
                {"kind": "OBJECT", "name": "User", "fields": [{"name": "id", "isDeprecated": False, "args": [], "type": {"kind": "SCALAR", "name": "ID", "ofType": None}}]},
            ],
        }}})

    @app.route("/roles/admin-vuln")
    def role_admin_vuln():
        return jsonify({"panel": "admin", "records": [1, 2, 3]})

    @app.route("/roles/admin-safe")
    def role_admin_safe():
        if request.headers.get("Authorization") != "Bearer high-role":
            return jsonify({"error": "forbidden"}), 403
        return jsonify({"panel": "admin", "records": [1, 2, 3]})

    @app.route("/oidc-safe")
    def oidc_safe():
        return jsonify({
            "issuer": "https://identity.example.test",
            "authorization_endpoint": "https://identity.example.test/authorize",
            "token_endpoint": "https://identity.example.test/token",
            "userinfo_endpoint": "https://identity.example.test/userinfo",
            "jwks_uri": "https://identity.example.test/jwks.json",
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        })

    @app.route("/oidc-risky")
    def oidc_risky():
        return jsonify({
            "issuer": "https://identity.example.test",
            "authorization_endpoint": "https://identity.example.test/authorize",
            "token_endpoint": "https://identity.example.test/token",
            "jwks_uri": "https://identity.example.test/jwks.json",
            "response_types_supported": ["code", "id_token token"],
            "code_challenge_methods_supported": [],
            "id_token_signing_alg_values_supported": ["none", "RS256"],
        })

    @app.route("/large")
    def large_response():
        return Response(b"A" * (3 * 1024 * 1024), mimetype="application/octet-stream")

    @app.route("/slow")
    def slow_response():
        import time
        time.sleep(0.35)
        return Response("slow", mimetype="text/plain")

    @app.route("/oast/<token>", methods=["GET", "POST"])
    def callback(token):
        execution_token = request.args.get("execution", "")
        event = "script_fetch" if execution_token else "callback"
        recorded = record_hit(token, {"event": event})
        return Response("/* isolated OAST fixture */", status=200 if recorded else 404, mimetype="application/javascript")

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        server.shutdown()
        thread.join(timeout=3)
