import requests
import time

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Rate Limiting",
    "severity": "Medium",
    "description": "Detects absence of rate limiting protections"
}

inputs = []  # 👈 no user input needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    success = 0
    blocked = 0
    delays = []

    try:
        for _ in range(15):
            start = time.time()

            try:
                res = requests.get(url, timeout=5)
                elapsed = time.time() - start

                delays.append(elapsed)

                if res.status_code == 200:
                    success += 1
                elif res.status_code == 429:
                    blocked += 1

            except:
                continue

        avg_delay = sum(delays) / len(delays) if delays else 0

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if success >= 15 and blocked == 0 and avg_delay < 1.5:
            return {
                "vulnerable": True,
                "result": "No rate limiting detected (multiple rapid requests succeeded)",
                "severity": "Medium"
            }

        if blocked > 0:
            return {
                "vulnerable": False,
                "result": "Rate limiting detected (HTTP 429 responses)",
                "severity": "Low"
            }

        if avg_delay > 2:
            return {
                "vulnerable": False,
                "result": "Server slowdown detected (possible protection)",
                "severity": "Low"
            }

        return {
            "vulnerable": False,
            "result": "Rate limiting behavior unclear",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }