import hashlib

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
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


def _masked_identifier(value):
    return f"sha256:{hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:12]}"


def _runtime_has_auth_context(runtime):
    if runtime is None:
        return False
    if runtime.cookies:
        return True
    auth_header_names = {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
    }
    return any(str(name).strip().lower() in auth_header_names for name in runtime.default_headers)


def scan(url, param="", authorized_id="", test_id="", private_marker="", auth_header_name="", auth_header_value=""):
    attempts = 0
    if not param or not authorized_id or not test_id:
        return inconclusive(
            "Parameter, authorized object ID, and denied test object ID are required.",
            evidence={"final_decision": "missing_required_inputs"},
            endpoint=url,
            requests_made=0,
        )
    if str(authorized_id) == str(test_id):
        return inconclusive(
            "Authorized and denied test object IDs must be different.",
            evidence={
                "authorized_id_hash": _masked_identifier(authorized_id),
                "test_id_hash": _masked_identifier(test_id),
                "final_decision": "identical_object_ids",
            },
            endpoint=url,
            parameter=param,
            requests_made=0,
        )

    if bool(auth_header_name) != bool(auth_header_value):
        return inconclusive(
            "A complete authorization context is required; provide both the auth header name and value.",
            evidence={"final_decision": "incomplete_auth_context"},
            endpoint=url,
            parameter=param,
            requests_made=0,
        )

    runtime = current_runtime()
    runtime_has_auth = _runtime_has_auth_context(runtime)
    supplied_auth = bool(auth_header_name and auth_header_value)
    if not supplied_auth and not runtime_has_auth:
        return inconclusive(
            "An explicit authorized header or active authenticated scan context is required.",
            evidence={"final_decision": "missing_auth_context"},
            endpoint=url,
            parameter=param,
            requests_made=0,
        )

    headers = {}
    if supplied_auth:
        headers[auth_header_name] = auth_header_value
    try:
        attempts += 1
        authorized = safe_request("GET", append_query_param(url, param, authorized_id), headers=headers)
        attempts += 1
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
            "protected_marker_matched": marker_exposed,
            "authorized_id_hash": _masked_identifier(authorized_id),
            "test_id_hash": _masked_identifier(test_id),
            "auth_context_supplied": True,
        }

        if tested.status_code == 200 and marker_exposed:
            evidence["final_decision"] = "confirmed_protected_marker_exposed"
            return make_result(
                True,
                "The object that should have been denied returned the configured private-data marker.",
                severity="High",
                confidence="High",
                evidence=evidence,
                recommendation="Enforce object-level authorization on every resource lookup and derive access from the authenticated principal, not the supplied ID.",
                endpoint=url,
                parameter=param,
                cwe="CWE-639",
                cvss=8.1,
                requests_made=attempts,
            )

        if tested.status_code == 200 and authorized.status_code == 200 and body_similarity >= 0.92 and len(tested_body) > 80:
            evidence["final_decision"] = "potential_response_parity"
            return make_result(
                True,
                "The denied object returned a highly similar successful response. This is a potential authorization flaw requiring manual confirmation.",
                severity="Medium",
                confidence="Low",
                status="potential",
                evidence=evidence,
                recommendation="Manually compare object ownership and enforce object-level authorization before returning data.",
                endpoint=url,
                parameter=param,
                cwe="CWE-639",
                cvss=6.5,
                requests_made=attempts,
            )

        evidence["final_decision"] = "authorization_bypass_not_observed"
        return make_result(
            False,
            "The nominated unauthorized object was denied or did not match the authorized private response.",
            severity="Info",
            confidence="High" if denial_status or private_marker else "Medium",
            evidence=evidence,
            endpoint=url,
            parameter=param,
            cwe="CWE-639",
            requests_made=attempts,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(
            f"IDOR authorization check failed: {exc}",
            evidence={"final_decision": "transport_or_processing_error"},
            endpoint=url,
            parameter=param,
            requests_made=attempts,
        )
