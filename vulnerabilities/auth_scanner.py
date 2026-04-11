import time
from concurrent.futures import ThreadPoolExecutor
from utils import get_session
from report import section, vuln, safe

def send_request(session, url, data):
    start = time.time()
    r = session.post(url, data=data)
    return r.status_code, time.time() - start

def check_broken_auth(url, user_field, pass_field):
    section("Broken Authentication")

    session = get_session()

    data = {
        user_field: "admin",
        pass_field: "wrongpass"
    }

    results = []

    def task():
        return send_request(session, url, data)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(task) for _ in range(15)]

        for f in futures:
            try:
                status, delay = f.result()
                results.append((status, delay))
                print(f"Status={status}, Time={delay:.2f}s")
            except:
                pass

    blocked = any(s == 429 for s, _ in results)
    slow = any(d > 2 for _, d in results)

    if not blocked and not slow:
        vuln("No Rate Limiting", "HIGH")
    elif slow:
        safe("Delay detected (possible protection)")
    else:
        safe("Rate limiting detected")