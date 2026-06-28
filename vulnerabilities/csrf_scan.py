from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from vulnerabilities.common import error_result, make_result, safe_request

meta = {
    "name": "CSRF Form Protection",
    "severity": "Medium",
    "description": "Inspects each state-changing HTML form for anti-CSRF controls.",
    "category": "Session Security",
}
inputs = []

TOKEN_HINTS = ("csrf", "xsrf", "authenticity", "requesttoken", "nonce")
STATE_CHANGING = {"post", "put", "patch", "delete"}


def _has_token(form):
    for element in form.find_all(["input", "button"]):
        name = (element.get("name") or "").lower().replace("_", "")
        element_id = (element.get("id") or "").lower().replace("_", "")
        if any(hint in name or hint in element_id for hint in TOKEN_HINTS):
            return True
    return False


def scan(url):
    try:
        response = safe_request("GET", url)
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return make_result(
                False,
                "The endpoint did not return HTML forms.",
                severity="Info",
                confidence="High",
                endpoint=response.url,
                requests_made=1,
            )

        soup = BeautifulSoup(response.text, "html.parser")
        forms = []
        missing = []
        protected = []

        for index, form in enumerate(soup.find_all("form"), start=1):
            method = (form.get("method") or "get").lower()
            action = urljoin(response.url, form.get("action") or response.url)
            if method not in STATE_CHANGING:
                continue
            entry = {"index": index, "method": method.upper(), "action": action}
            forms.append(entry)
            if _has_token(form):
                protected.append(entry)
            else:
                missing.append(entry)

        if not forms:
            return make_result(
                False,
                "No state-changing HTML forms were found.",
                severity="Info",
                confidence="High",
                endpoint=response.url,
                requests_made=1,
            )

        if missing:
            return make_result(
                True,
                f"{len(missing)} of {len(forms)} state-changing form(s) have no visible anti-CSRF token. This is an indicator; server-side validation and SameSite behavior still require manual verification.",
                severity="Medium",
                confidence="Medium",
                status="potential",
                evidence={"missing_token_forms": missing, "protected_forms": protected},
                recommendation="Add a server-validated, per-session anti-CSRF token to every state-changing form and use SameSite cookies as defense in depth.",
                endpoint=response.url,
                cwe="CWE-352",
                cvss=6.5,
                requests_made=1,
            )

        return make_result(
            False,
            "All discovered state-changing forms contain a visible anti-CSRF token field.",
            severity="Info",
            confidence="Medium",
            evidence={"protected_forms": protected},
            endpoint=response.url,
            cwe="CWE-352",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"CSRF form inspection failed: {exc}", endpoint=url)
