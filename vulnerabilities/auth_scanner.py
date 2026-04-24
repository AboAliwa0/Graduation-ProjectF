import time
from concurrent.futures import ThreadPoolExecutor
import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Broken Authentication",
    "severity": "High",
    "description": "Detects lack of rate limiting or brute force protection"
}

# inputs required from user
inputs = ["login_url", "username_field", "password_field"]


# -----------------------
# 🚀 CORE FUNCTIONS
# -----------------------

def send_request(session, url, data):
    start = time.time()
    r = session.post(url, data=data)
    return r.status_code, time.time() - start


def scan(url, login_url, username_field="username", password_field="password"):
    session = requests.Session()

    data = {
        username_field: "admin",
        password_field: "wrongpass"
    }

    results = []

    def task():
        return send_request(session, login_url, data)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(task) for _ in range(10)]

        for f in futures:
            try:
                status, delay = f.result()
                results.append((status, delay))
            except:
                pass

    blocked = any(s == 429 for s, _ in results)
    slow = any(d > 2 for _, d in results)

    # -----------------------
    # 📊 RESULT
    # -----------------------

    if not blocked and not slow:
        return {
            "vulnerable": True,
            "result": "No rate limiting detected (Brute-force possible)",
            "severity": "High"
        }

    elif slow:
        return {
            "vulnerable": False,
            "result": "Server delay detected (possible protection)",
            "severity": "Medium"
        }

    else:
        return {
            "vulnerable": False,
            "result": "Rate limiting detected",
            "severity": "Low"
        }