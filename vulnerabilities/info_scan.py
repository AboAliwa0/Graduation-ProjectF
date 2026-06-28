from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import re

from vulnerabilities.common import body_text, error_result, highest_severity, make_result, safe_request

meta = {
    "name": "Information Disclosure",
    "severity": "Medium",
    "description": "Detects stack traces, exposed secrets, debug pages, and verbose technology headers.",
    "category": "Exposure",
}
inputs = []

PATTERNS = [
    ("python_traceback", re.compile(r"Traceback \(most recent call last\):", re.I), "High"),
    ("java_stacktrace", re.compile(r"(?:java\.|javax\.)[\w.$]+Exception", re.I), "High"),
    ("dotnet_stacktrace", re.compile(r"System\.[\w.]+Exception", re.I), "High"),
    ("database_error", re.compile(r"SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}", re.I), "Medium"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Critical"),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Critical"),
    ("debug_mode", re.compile(r"Werkzeug Debugger|DEBUG\s*=\s*True|Whoops! There was an error", re.I), "High"),
]


def scan(url):
    try:
        response = safe_request("GET", url)
        text = body_text(response)
        observations = []
        for name, pattern, severity in PATTERNS:
            match = pattern.search(text)
            if match:
                observations.append({"type": name, "severity": severity, "sample": match.group(0)[:120]})

        verbose_headers = {}
        for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"):
            if response.headers.get(header):
                verbose_headers[header] = response.headers[header]

        if observations:
            severity = highest_severity(item["severity"] for item in observations)
            return make_result(
                True,
                "Sensitive diagnostic or secret-like content was exposed in the response.",
                severity=severity,
                confidence="High",
                evidence={"matches": observations, "technology_headers": verbose_headers},
                recommendation="Disable debug output, replace detailed errors with generic responses, and rotate any exposed credentials immediately.",
                endpoint=response.url,
                cwe="CWE-200",
                cvss=9.1 if severity == "Critical" else 7.5 if severity == "High" else 5.3,
                requests_made=1,
            )

        return make_result(
            False,
            "No sensitive diagnostic disclosure was detected. Technology headers, when present, are recorded as metadata rather than treated as a vulnerability.",
            severity="Info",
            confidence="High",
            evidence={"technology_headers": verbose_headers},
            endpoint=response.url,
            cwe="CWE-200",
            requests_made=1,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Information-disclosure check failed: {exc}", endpoint=url)
