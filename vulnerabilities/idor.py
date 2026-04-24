from utils.requester import send_request

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "IDOR (BOLA)",
    "severity": "High",
    "description": "Tests for Insecure Direct Object Reference via ID manipulation"
}

inputs = ["param"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, param):
    test_ids = ["1", "2", "3", "999"]
    responses = []

    try:
        for i in test_ids:
            test_url = f"{url}?{param}={i}"
            res = send_request(test_url)

            # normalize response (shorten for comparison)
            responses.append(res[:200])

        # -----------------------
        # 📊 ANALYSIS
        # -----------------------

        unique_responses = set(responses)

        if len(unique_responses) > 1:
            return {
                "vulnerable": True,
                "result": "Different responses detected for ID values (possible IDOR)",
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "No IDOR behavior detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }