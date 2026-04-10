import requests

def scan(url):
    results = []
    success = 0

    for _ in range(20):
        try:
            res = requests.get(url)
            if res.status_code == 200:
                success += 1
        except:
            pass

    if success == 20:
        results.append({
            "type": "Missing Rate Limiting",
            "payload": "20 rapid requests",
            "status": "Potentially Vulnerable",
            "risk": "Medium"
        })

    return results