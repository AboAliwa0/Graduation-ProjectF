import requests

def scan(url):
    try:
        files = {
            'file': ('test.php', '<?php echo "test"; ?>')
        }

        response = requests.post(url, files=files)

        if response.status_code == 200:
            return "[+] File Upload Possible"

        return "[-] File Upload Not Vulnerable"

    except:
        return "[!] Error in File Upload Test"