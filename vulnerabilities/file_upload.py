import requests

# -----------------------
# 🧠 META
# -----------------------

meta = {
    "name": "File Upload",
    "severity": "High",
    "description": "Tests if server allows uploading executable files"
}

# 👇 user must provide upload endpoint
inputs = ["upload_url"]


# -----------------------
# 🚀 SCAN
# -----------------------

def scan(url, upload_url=None):
    if not upload_url:
        return {
            "vulnerable": False,
            "result": "Upload URL not provided",
            "severity": "Low"
        }

    try:
        files = {
            'file': ('test.php', '<?php echo "vuln"; ?>', 'application/x-php')
        }

        response = requests.post(upload_url, files=files, timeout=10)

        # 🔥 smarter detection
        if response.status_code == 200 and "error" not in response.text.lower():
            return {
                "vulnerable": True,
                "result": "Server accepted file upload (potential RCE risk)",
                "severity": "High"
            }

        return {
            "vulnerable": False,
            "result": "File upload rejected or restricted",
            "severity": "Low"
        }

    except Exception as e:
        return {
            "vulnerable": False,
            "result": f"Error: {str(e)}",
            "severity": "Low"
        }