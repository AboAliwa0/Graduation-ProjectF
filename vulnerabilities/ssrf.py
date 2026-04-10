from utils.requester import send_request

def scan(url, param):
    payload = "http://127.0.0.1"
    full_url = f"{url}?{param}={payload}"

    response = send_request(full_url)

    if "127.0.0.1" in response or "localhost" in response:
        return [{
            "type": "SSRF",
            "payload": payload,
            "status": "Potentially Vulnerable",
            "risk": "High"
        }]

    return []