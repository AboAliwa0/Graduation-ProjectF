from utils.requester import send_request

def scan(url, param):
    payloads = ["<h1>TEST123</h1>", "<b>INJECT</b>"]
    results = []

    for payload in payloads:
        full_url = f"{url}?{param}={payload}"
        response = send_request(full_url)

        if payload in response:
            results.append({
                "type": "HTML Injection",
                "payload": payload,
                "status": "Vulnerable",
                "risk": "Medium"
            })

    return results