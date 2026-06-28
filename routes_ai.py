from flask import Blueprint, jsonify, request, session
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from ai_analyzer import analyze_scan

ai_bp = Blueprint("ai", __name__)
MAX_ANALYSIS_FINDINGS = 100


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
