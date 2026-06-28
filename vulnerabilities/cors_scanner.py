from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from vulnerabilities.common import error_result, highest_severity, make_result, safe_request

meta = {
    "name": "CORS Misconfiguration",
    "severity": "High",
    "description": "Checks arbitrary-origin reflection, null origins, credentials, and preflight behavior.",
    "category": "Security Configuration",
}
inputs = []

TEST_ORIGINS = ("https://cyberscan.invalid", "null")


def scan(url):
    findings = []
    requests_made = 0
    try:
        for origin in TEST_ORIGINS:
            response = safe_request("GET", url, headers={"Origin": origin})
            requests_made += 1
            allow_origin = response.headers.get("Access-Control-Allow-Origin", "").strip()
            credentials = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"

            if allow_origin == origin:
                severity = "High" if credentials else "Medium"
                findings.append({
                    "issue": "arbitrary_origin_reflection",
                    "origin": origin,
                    "credentials": credentials,
                    "severity": severity,
                })
            elif origin == "null" and allow_origin == "null":
                findings.append({
                    "issue": "null_origin_allowed",
                    "origin": origin,
                    "credentials": credentials,
                    "severity": "High" if credentials else "Medium",
                })
            elif allow_origin == "*" and credentials:
                # Browsers reject wildcard + credentials, so this is a bad policy but not
                # the same as credentialed arbitrary-origin access.
                findings.append({
                    "issue": "invalid_wildcard_credentials_combination",
                    "origin": origin,
                    "credentials": True,
                    "severity": "Low",
                })

        preflight_origin = TEST_ORIGINS[0]
        preflight = safe_request(
            "OPTIONS",
            url,
            headers={
                "Origin": preflight_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        requests_made += 1
        preflight_allow = preflight.headers.get("Access-Control-Allow-Origin", "").strip()
        preflight_creds = preflight.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
        if preflight_allow == preflight_origin:
            findings.append({
                "issue": "preflight_allows_arbitrary_origin",
                "origin": preflight_origin,
                "credentials": preflight_creds,
                "severity": "High" if preflight_creds else "Medium",
            })

        if findings:
            severity = highest_severity(item["severity"] for item in findings)
            confidence = "High" if any(item.get("credentials") for item in findings) else "Medium"
            return make_result(
                True,
                "Potentially unsafe CORS behavior was observed.",
                severity=severity,
                confidence=confidence,
                evidence={"observations": findings},
                recommendation="Use a strict origin allowlist, never reflect untrusted origins, and enable credentials only for trusted origins.",
                endpoint=url,
                cwe="CWE-942",
                cvss=8.1 if severity == "High" else 5.3,
                requests_made=requests_made,
            )

        return make_result(
            False,
            "No arbitrary-origin CORS behavior was detected.",
            severity="Info",
            confidence="High",
            evidence={"tested_origins": list(TEST_ORIGINS)},
            endpoint=url,
            cwe="CWE-942",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"CORS check failed: {exc}", endpoint=url, requests_made=requests_made)
