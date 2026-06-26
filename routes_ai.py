from flask import Blueprint, request, jsonify, session
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from ai_analyzer import analyze_scan

ai_bp = Blueprint("ai", __name__)


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
        return jsonify({"error": "Unauthorized. Login is required for AI analysis."}), 401

    data = request.get_json(silent=True) or {}

    scan_results = data.get("scan_results", [])

    result = analyze_scan(scan_results)

    return jsonify(result)
