import requests

def scan_info(url):
    res = requests.get(url)

    if "error" in res.text.lower() or "apache" in res.text.lower():
        return "[!] Information Disclosure Detected"

    return "[+] Safe"