import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "Directory Listing",
    "severity": "Medium",
    "description": "Detects exposed directories with index listing enabled"
}

inputs = []  # 👈 no inputs needed


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url):
    common_paths = [
        "uploads/",
        "images/",
        "backup/",
        "admin/",
        "files/"
    ]

    found = []

    try:
        for path in common_paths:
            full_url = url.rstrip("/") + "/" + path

            try:
                res = requests.get(full_url, timeout=5)

                if "index of" in res.text.lower():
                    found.append(full_url)

            except:
                continue

        # -----------------------
        # 📊 RESULT
        # -----------------------

        if found:
            return {
                "vulnerable": True,
                "result": f"Directory listing enabled: {', '.join(found)}",
                "severity": "Medium"
            }

        return {
            "vulnerable": False,
            "result": "No directory listing detected",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }