import re

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
    is_arabic = bool(re.search(r"[\u0600-\u06ff]", text))
    sensitive = (
        r"(?i)\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|authorization|cookie|session)\b\s*[:=]",
        r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}",
        r"\b(?:\d[ -]*?){13,19}\b",
    )
    if any(re.search(pattern, message) for pattern in sensitive):
        answer = ("من فضلك لا ترسل كلمات مرور أو Tokens أو Cookies أو مفاتيح API أو بيانات دفع. لم يتم حفظ محتوى رسالتك أو استخدامه للوصول إلى حسابك. احذف البيانات الحساسة واسأل بصيغة عامة." if is_arabic else
                  "Please do not send passwords, tokens, cookies, API keys, or payment data. Your message was not stored or used to access your account. Remove the sensitive value and ask the question in general terms.")
        return answer, []
    harmful = ("steal password", "hack account", "bypass login", "ransomware", "malware", "exploit real", "سرقة", "اختراق حساب", "تجاوز تسجيل")
    if any(term in text for term in harmful):
        return "I can help you learn defensive security or test systems you own, but I cannot guide unauthorized access. Try asking how to prevent or safely verify the issue in a local lab.", [{"label": "Open Learning", "url": "/learning"}]
    if any(term in text for term in ("private", "privacy", "my password", "my token", "بيانات", "خصوصية", "كلمة السر")):
        answer = ("أنا لا أقرأ قاعدة البيانات أو كلمات المرور أو Cookies أو نتائج الفحص الخاصة بك، ولا أحتاجها للإجابة. أرسل سؤالًا عامًا فقط ولا تضع أي أسرار داخل المحادثة." if is_arabic else
                  "I do not read the database, passwords, cookies, or your private scan results. I do not need them to answer. Ask in general terms and never paste secrets into chat.")
        return answer, []
    for key, answer in SECURITY_TOPICS.items():
        if key in text:
            return answer + " Use CyberScan only on targets you own or have written permission to test.", [{"label": "Learn this topic", "url": "/learning"}, {"label": "Start authorized scan", "url": "/dashboard"}]
    if any(term in text for term in ("learn", "lesson", "course", "quiz", "تعلم", "درس", "اختبار")):
        return "The Learning Center gives students a 17-lesson path with guides, quizzes, safe labs, XP, streaks, and a completion certificate. Your progress is saved to your account.", [{"label": "Open Learning Center", "url": "/learning"}]
    if any(term in text for term in ("scope", "allowed target", "authorized target", "نطاق", "هدف مسموح")):
        return "Scopes define the hostnames you are authorized to scan. From Dashboard choose Add Scope, enter the hostname, decide whether subdomains are included, and save it before scanning.", [{"label": "Manage scopes", "url": "/dashboard"}]
    if any(term in text for term in ("quick", "standard", "deep", "modern", "mode", "وضع", "سريع", "عميق")):
        return "Quick runs a small low-cost module set, Standard provides balanced coverage, Deep selects broader checks with a larger request budget, and Modern focuses on SPA, API, WebSocket, OpenAPI and related technologies.", [{"label": "Choose scan mode", "url": "/dashboard"}]
    if any(term in text for term in ("budget", "request count", "requests", "ميزانية", "طلبات")):
        return "Request Budget is the maximum network work a scan may perform. Quick defaults to 60, Standard to 120, Modern to 250, and Deep to 300. Use the smallest budget that covers your authorized test.", [{"label": "Configure a scan", "url": "/dashboard"}]
    if any(term in text for term in ("cancel", "queued", "running", "interrupted", "status", "إلغاء", "حالة", "قيد التشغيل")):
        return "Queued is waiting, Running is active, Cancelling is stopping safely, Done completed, Failed encountered an error, and Interrupted means the application restarted during a local job. Active scans can be cancelled from Dashboard.", [{"label": "View scan status", "url": "/dashboard"}]
    if any(term in text for term in ("scan", "scanner", "فحص", "اسكان")):
        return "Open Dashboard, choose New Scan, enter an authorized HTTP or HTTPS target, select the relevant modules and request budget, then start the scan. Begin with Quick mode if you are new.", [{"label": "Open Dashboard", "url": "/dashboard"}]
    if any(term in text for term in ("report", "export", "history", "تقرير", "نتائج", "سجل")):
        return "Scan History stores your previous scans. Open a completed scan to review evidence and recommendations, then export PDF, JSON, SARIF, sanitized HAR, or artifacts as needed.", [{"label": "View Scan History", "url": "/history"}]
    if any(term in text for term in ("pdf", "json", "sarif", "har", "artifact", "تصدير")):
        return "PDF is best for human review, JSON for integrations, SARIF for developer security tools, sanitized HAR for a safe network inventory, and Artifacts for scanner-collected evidence with secrets omitted.", [{"label": "Open scan history", "url": "/history"}]
    if any(term in text for term in ("register", "login", "student", "developer", "تسجيل", "طالب", "مطور")):
        return "Choose Student during registration to access the Learning Center. Developer accounts get the professional scanning dashboard without the learning section. Your account type is stored in the database.", [{"label": "Create account", "url": "/register"}, {"label": "Sign in", "url": "/login"}]
    if any(term in text for term in ("this page", "current page", "here", "الصفحة دي", "الصفحة الحالية", "هنا")):
        page_help = {
            "/": "This is the CyberScan introduction page. Use it to understand the platform, then register or sign in.",
            "/login": "This page signs you in securely with your registered email and password.",
            "/register": "Create an account here and choose Student for learning features or Developer for the scanning workspace.",
            "/dashboard": "Dashboard is your scan workspace: manage scopes, start scans, monitor progress, inspect findings, and export results.",
            "/history": "Scan History lists your previous jobs. Select one to inspect status, findings, evidence, and exports.",
            "/learning": "Learning Center provides the guided student path, videos, guides, quizzes, labs, XP, streaks, and certificates.",
        }
        return page_help.get(page, "This page is part of CyberScan. Tell me the control or result you want help with and I will guide you."), []
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
