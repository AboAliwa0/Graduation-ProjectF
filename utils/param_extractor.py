import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

def extract_params(url):
    params = set()

    try:
        # 🔹 استخراج من URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        for param in query_params:
            params.add(param)

        # 🔹 استخراج من HTML forms
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                if name:
                    params.add(name)

    except:
        pass

    return list(params)