import requests

def scan_csrf(url):
    res = requests.get(url)

    if "csrf" not in res.text.lower():
        return "[!] Possible CSRF Vulnerability"

    return "[+] CSRF Protection Found"
    