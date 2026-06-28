from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from vulnerabilities.common import append_query_param, body_text, error_result, inconclusive, make_result, safe_request, similarity

meta = {
    "name": "IDOR / Object Authorization",
    "severity": "High",
    "description": "Compares an authorized object with a nominated unauthorized object using the same test account.",
    "category": "Access Control",
}
inputs = [
    {"name": "param", "label": "Object ID parameter", "type": "text", "required": True, "placeholder": "id"},
    {"name": "authorized_id", "label": "Authorized object ID", "type": "text", "required": True, "placeholder": "1001"},
    {"name": "test_id", "label": "Object ID that should be denied", "type": "text", "required": True, "placeholder": "1002"},
    {"name": "private_marker", "label": "Expected private-data marker", "type": "text", "required": False, "placeholder": "account_owner"},
    {"name": "auth_header_name", "label": "Auth header name", "type": "text", "required": False, "placeholder": "Authorization"},
    {"name": "auth_header_value", "label": "Auth header value", "type": "password", "required": False, "placeholder": "Bearer ..."},
]


def scan(url, param="", authorized_id="", test_id="", private_marker="", auth_header_name="", auth_header_value=""):
    if not param or not authorized_id or not test_id:
        return inconclusive("Parameter, authorized object ID, and denied test object ID are required.", endpoint=url)
    headers = {}
    if auth_header_name and auth_header_value:
        headers[auth_header_name] = auth_header_value
    try:
        authorized = safe_request("GET", append_query_param(url, param, authorized_id), headers=headers)
        tested = safe_request("GET", append_query_param(url, param, test_id), headers=headers)
        authorized_body = body_text(authorized)
        tested_body = body_text(tested)
        body_similarity = similarity(authorized_body, tested_body)
        marker_exposed = bool(private_marker and private_marker in tested_body)
        denial_status = tested.status_code in {401, 403, 404}
        evidence = {
            "authorized_status": authorized.status_code,
            "tested_status": tested.status_code,
            "body_similarity": round(body_similarity, 3),
            "private_marker_exposed": marker_exposed,
            "authorized_id": authorized_id,
            "test_id": test_id,
        }

        if tested.status_code == 200 and marker_exposed:
            return make_result(
                True,
                "The object that should have been denied returned the configured private-data marker.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Enforce object-level authorization on every resource lookup and derive access from the authenticated principal, not the supplied ID.",
                endpoint=tested.url,
                parameter=param,
                cwe="CWE-639",
                cvss=8.1,
                requests_made=2,
            )

        if tested.status_code == 200 and authorized.status_code == 200 and body_similarity >= 0.92 and len(tested_body) > 80:
            return make_result(
                True,
                "The denied object returned a highly similar successful response. This is a potential authorization flaw requiring manual confirmation.",
                severity="Medium",
                confidence="Low",
                status="potential",
                evidence=evidence,
                recommendation="Manually compare object ownership and enforce object-level authorization before returning data.",
                endpoint=tested.url,
                parameter=param,
                cwe="CWE-639",
                cvss=6.5,
                requests_made=2,
            )

        return make_result(
            False,
            "The nominated unauthorized object was denied or did not match the authorized private response.",
            severity="Info",
            confidence="High" if denial_status or private_marker else "Medium",
            evidence=evidence,
            endpoint=tested.url,
            parameter=param,
            cwe="CWE-639",
            requests_made=2,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"IDOR authorization check failed: {exc}", endpoint=url, parameter=param)
