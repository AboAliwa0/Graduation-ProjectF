import html as html_lib

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from bs4 import BeautifulSoup
from vulnerabilities.common import append_query_param, body_text, error_result, make_result, safe_request, unique_token

meta = {
    "name": "Reflected HTML Injection",
    "severity": "Medium",
    "description": "Uses a harmless custom element to confirm unescaped reflected markup.",
    "category": "Injection",
}
inputs = [
    {"name": "param", "label": "Parameter", "type": "text", "required": True, "placeholder": "q"}
]


def scan(url, param=""):
    if not param:
        return make_result(
            False,
            "A parameter name is required.",
            status="inconclusive",
            endpoint=url,
            parameter=param,
            evidence={"parameter": param, "reason": "missing_required_parameter"},
            requests_made=0,
        )
    token = unique_token("html")
    payload = f'<cyberscan-probe data-token="{token}">safe</cyberscan-probe>'
    requests_made = 0
    try:
        requests_made += 1
        baseline = safe_request("GET", append_query_param(url, param, token))
        requests_made += 1
        response = safe_request("GET", append_query_param(url, param, payload))
        content_type = response.headers.get("Content-Type", "").lower()
        body = body_text(response)
        decoded_body = html_lib.unescape(body)
        soup = BeautifulSoup(body, "html.parser") if "html" in content_type else None
        element = soup.find("cyberscan-probe", attrs={"data-token": token}) if soup else None
        inert_context = element.find_parent(["textarea", "title", "style", "xmp", "noscript", "template"]) is not None if element else False
        confirmed = bool(element) and not inert_context and payload not in body_text(baseline)
        evidence = {
            "parameter": param,
            "token": token,
            "content_type": response.headers.get("Content-Type", ""),
            "status_code": response.status_code,
            "reflected_raw": payload in body,
            "reflected_decoded": payload in decoded_body,
            "exact_markup_reflected": payload in body,
            "custom_element_parsed": bool(element),
            "inert_html_context": inert_context,
            "final_decision": "parsed_custom_element_confirmed" if confirmed else "no_parsed_custom_element_confirmed",
        }
        if confirmed:
            return make_result(
                True,
                "Unescaped attacker-controlled HTML markup was reflected in an HTML response.",
                severity="Medium",
                confidence="High",
                evidence=evidence,
                recommendation="Contextually encode reflected data and sanitize HTML only when rich text is explicitly required.",
                endpoint=response.url,
                parameter=param,
                cwe="CWE-79",
                cvss=6.1,
                requests_made=requests_made,
            )
        return make_result(
            False,
            "No unescaped reflected HTML markup was confirmed.",
            severity="Info",
            confidence="High",
            evidence=evidence,
            endpoint=response.url,
            parameter=param,
            cwe="CWE-79",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"HTML-injection check failed: {exc}", endpoint=url, parameter=param, requests_made=requests_made)
