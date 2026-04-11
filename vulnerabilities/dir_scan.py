import requests

def scan_directory(url):
    paths = ["uploads/", "images/", "backup/"]

    for path in paths:
        full_url = url + "/" + path
        res = requests.get(full_url)

        if "Index of" in res.text:
            return f"[!] Directory Listing Found: {full_url}"

    return "[+] No Directory Listing"