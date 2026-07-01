from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from urllib.parse import urlparse

from vulnerabilities.common import body_text, error_result, make_result, safe_request, unique_token

meta = {
    "name": "Host Header Injection",
    "severity": "Medium",
    "description": "Checks whether an untrusted Host/X-Forwarded-Host value is used in response content or redirects.",
    "category": "Request Routing",
}
inputs = []


def scan(url):
    marker = f"{unique_token('host')}.invalid"
    observations = []
    requests_made = 0
    try:
        for header_name in ("Host", "X-Forwarded-Host"):
            requests_made += 1
            response = safe_request("GET", url, headers={header_name: marker}, allow_redirects=False)
            body = body_text(response)
            location = response.headers.get("Location", "")
            reflected_body = marker.lower() in body.lower()
            reflected_location = marker.lower() in location.lower()
            if reflected_body or reflected_location:
                reflection_context = []
                if reflected_location:
                    reflection_context.append("location")
                if reflected_body:
                    reflection_context.append("body")
                observations.append({
                    "header": header_name,
                    "tested_host": marker,
                    "status_code": response.status_code,
                    "reflected_in_body": reflected_body,
                    "reflected_in_location": reflected_location,
                    "reflection_context": reflection_context,
                    "location": location,
                })

        if observations:
            high_confidence = any(item["reflected_in_location"] for item in observations)
            return make_result(
                True,
                "An attacker-controlled host value was used in a redirect." if high_confidence else "An attacker-controlled host value was reflected in response content; exploitability requires manual validation.",
                severity="High" if high_confidence else "Medium",
                confidence="High" if high_confidence else "Low",
                status="confirmed" if high_confidence else "potential",
                evidence={"tested_host": marker, "observations": observations},
                recommendation="Validate Host headers against an allowlist and configure trusted proxy headers explicitly.",
                endpoint=url,
                cwe="CWE-644",
                cvss=8.1 if high_confidence else 5.3,
                requests_made=requests_made,
            )
        return make_result(
            False,
            "No attacker-controlled host reflection was observed.",
            severity="Info",
            confidence="High",
            evidence={"tested_host": marker, "target_host": urlparse(url).hostname, "observations": observations},
            endpoint=url,
            cwe="CWE-644",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Host-header check failed: {exc}", endpoint=url, requests_made=requests_made)
