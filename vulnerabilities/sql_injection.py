from utils.requester import send_request

def scan(url, param):
    payload_true = "' OR '1'='1"
    payload_false = "' OR '1'='2"

    url_true = f"{url}?{param}={payload_true}"
    url_false = f"{url}?{param}={payload_false}"

    res_true = send_request(url_true)
    res_false = send_request(url_false)

    if res_true != res_false:
        return [{
            "type": "SQL Injection (Boolean Based)",
            "payload": payload_true,
            "status": "Potentially Vulnerable",
            "risk": "High"
        }]

    return []