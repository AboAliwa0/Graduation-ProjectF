from utils import get_session
from report import section, vuln, safe

def check_graphql_abuse(url):
    section("GraphQL")

    session = get_session()

    query = {
        "query": "{ __schema { types { name } } }"
    }

    try:
        r = session.post(url, json=query)
        data = r.json()

        if "data" in data:
            vuln("GraphQL Introspection Enabled", "MEDIUM")
        else:
            safe("No issue detected")

    except:
        safe("Request failed")