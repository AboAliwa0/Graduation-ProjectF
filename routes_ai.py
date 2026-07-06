from flask import Blueprint, jsonify, request, session
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from ai_analyzer import analyze_scan

ai_bp = Blueprint("ai", __name__)
MAX_ANALYSIS_FINDINGS = 100
MAX_ASSISTANT_MESSAGE = 800

SECURITY_TOPICS = {
    "sql injection": "SQL Injection happens when untrusted input becomes part of a database query. Use parameterized queries, server-side validation, and least-privilege database accounts.",
    "sqli": "SQL Injection happens when untrusted input becomes part of a database query. Use parameterized queries, server-side validation, and least-privilege database accounts.",
    "xss": "Cross-Site Scripting lets untrusted content execute in a browser. Apply context-aware output encoding, sanitize allowed HTML, and use a restrictive Content Security Policy.",
    "csrf": "CSRF tricks a signed-in browser into sending an unwanted request. Protect state-changing requests with CSRF tokens, SameSite cookies, and origin checks.",
    "idor": "IDOR is broken object-level authorization. The server must verify that the current user may access every requested record, regardless of the ID supplied by the client.",
    "cors": "CORS should allow only exact trusted origins. Never reflect arbitrary origins while credentials are enabled.",
    "clickjacking": "Prevent clickjacking with CSP frame-ancestors and, where appropriate, X-Frame-Options DENY or SAMEORIGIN.",
    "path traversal": "Path Traversal abuses file paths such as ../. Resolve paths safely, use allowlists, and verify the final path stays inside the intended directory.",
    "authentication": "Secure authentication needs strong password storage, rate limiting, MFA where possible, secure sessions, and generic login errors.",
    "rate limit": "Rate limiting constrains brute force, enumeration, and resource exhaustion. Apply limits per account, IP, and sensitive endpoint.",
    "websocket": "WebSockets require authentication, authorization, origin validation, message validation, and sensible size and rate limits.",
}


def assistant_answer(message: str, page: str = "") -> tuple[str, list[dict[str, str]]]:
    text = " ".join(message.lower().split())
    harmful = ("steal password", "hack account", "bypass login", "ransomware", "malware", "exploit real", "سرقة", "اختراق حساب", "تجاوز تسجيل")
    if any(term in text for term in harmful):
        return "I can help you learn defensive security or test systems you own, but I cannot guide unauthorized access. Try asking how to prevent or safely verify the issue in a local lab.", [{"label": "Open Learning", "url": "/learning"}]
    for key, answer in SECURITY_TOPICS.items():
        if key in text:
            return answer + " Use CyberScan only on targets you own or have written permission to test.", [{"label": "Learn this topic", "url": "/learning"}, {"label": "Start authorized scan", "url": "/dashboard"}]
    if any(term in text for term in ("learn", "lesson", "course", "quiz", "تعلم", "درس", "اختبار")):
        return "The Learning Center gives students a 17-lesson path with guides, quizzes, safe labs, XP, streaks, and a completion certificate. Your progress is saved to your account.", [{"label": "Open Learning Center", "url": "/learning"}]
    if any(term in text for term in ("scan", "scanner", "فحص", "اسكان")):
        return "Open Dashboard, choose New Scan, enter an authorized HTTP or HTTPS target, select the relevant modules and request budget, then start the scan. Begin with Quick mode if you are new.", [{"label": "Open Dashboard", "url": "/dashboard"}]
    if any(term in text for term in ("report", "export", "history", "تقرير", "نتائج", "سجل")):
        return "Scan History stores your previous scans. Open a completed scan to review evidence and recommendations, then export PDF, JSON, SARIF, sanitized HAR, or artifacts as needed.", [{"label": "View Scan History", "url": "/history"}]
    if any(term in text for term in ("register", "login", "student", "developer", "تسجيل", "طالب", "مطور")):
        return "Choose Student during registration to access the Learning Center. Developer accounts get the professional scanning dashboard without the learning section. Your account type is stored in the database.", [{"label": "Create account", "url": "/register"}, {"label": "Sign in", "url": "/login"}]
    return "I can help with CyberScan navigation, authorized scanning, reports, the student learning path, and web-security concepts such as XSS, SQL Injection, CSRF, IDOR, CORS, and authentication. What would you like to understand?", [{"label": "Dashboard", "url": "/dashboard"}, {"label": "Learning Center", "url": "/learning"}]


def current_user_id():
    if "user_id" in session:
        return session["user_id"]
    try:
        verify_jwt_in_request(optional=True)
        return get_jwt_identity()
    except Exception:
        return None


@ai_bp.route("/ai-analysis", methods=["POST"])
def ai_analysis():
    if not current_user_id():
        return jsonify({"error": "Unauthorized. Login is required for analysis."}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    scan_results = data.get("scan_results", [])
    if not isinstance(scan_results, list):
        return jsonify({"error": "scan_results must be a list."}), 400
    if len(scan_results) > MAX_ANALYSIS_FINDINGS:
        return jsonify({"error": f"A maximum of {MAX_ANALYSIS_FINDINGS} findings can be analyzed at once."}), 413
    return jsonify(analyze_scan(scan_results))


@ai_bp.route("/api/assistant", methods=["POST"])
def assistant_chat():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"error": "Please enter a question."}), 400
    if len(message) > MAX_ASSISTANT_MESSAGE:
        return jsonify({"error": f"Question must be {MAX_ASSISTANT_MESSAGE} characters or fewer."}), 413
    answer, actions = assistant_answer(message, str(data.get("page", ""))[:120])
    return jsonify({"answer": answer, "actions": actions, "mode": "local_security_assistant"})
