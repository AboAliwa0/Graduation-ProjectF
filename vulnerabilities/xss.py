from utils.requester import send_request

def scan(url, param):
    payload = "<script>alert('XSS')</script>"
    full_url = f"{url}?{param}={payload}"

    response = send_request(full_url)

    if payload in response:
        return [{
            "type": "Reflected XSS",
            "payload": payload,
            "status": "Vulnerable",
            "risk": "High"
        }]

    return []