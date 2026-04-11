import requests
import time

# ✅ session موحد لكل المشروع
def get_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Ascan Scanner)"
    })
    return session


# ✅ delay بين الطلبات (عشان rate limiting)
def rate_sleep(seconds=1):
    time.sleep(seconds)