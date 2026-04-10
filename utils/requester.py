import requests

def send_request(url):
    try:
        response = requests.get(url)
        return response.text
    except:
        return ""