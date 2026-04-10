from utils.requester import send_request

def scan(url, param):
    ids = ["1", "2", "3", "999"]
    responses = []

    for i in ids:
        full_url = f"{url}?{param}={i}"
        res = send_request(full_url)
        responses.append(res)

    if len(set(responses)) > 1:
        return [{
            "type": "IDOR (BOLA)",
            "payload": "ID Manipulation",
            "status": "Potentially Vulnerable",
            "risk": "High"
        }]

    return []