from flask import Blueprint, request, jsonify
from ai_analyzer import analyze_scan

ai_bp = Blueprint("ai", __name__)

@ai_bp.route("/ai-analysis", methods=["POST"])
def ai_analysis():

    data = request.get_json()

    scan_results = data.get("scan_results", [])

    result = analyze_scan(scan_results)

    return jsonify(result)