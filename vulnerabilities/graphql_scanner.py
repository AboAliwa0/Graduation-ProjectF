import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "GraphQL Introspection",
    "severity": "Medium",
    "description": "Detects if GraphQL introspection is enabled"
}

# 👇 user must provide GraphQL endpoint
inputs = ["endpoint"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, endpoint=None):
    if not endpoint:
        return {
            "vulnerable": False,
            "result": "GraphQL endpoint not provided",
            "severity": "Low"
        }

    query = {
        "query": "{ __schema { types { name } } }"
    }

    try:
        r = requests.post(endpoint, json=query, timeout=10)

        try:
            data = r.json()
        except:
            return {
                "vulnerable": False,
                "result": "Invalid JSON response",
                "severity": "Low"
            }

        if "data" in data:
            return {
                "vulnerable": True,
                "result": "GraphQL introspection is enabled",
                "severity": "Medium"
            }

        return {
            "vulnerable": False,
            "result": "No introspection detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }