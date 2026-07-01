from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import re

from vulnerabilities.common import (
    append_query_param,
    body_text,
    error_result,
    highest_severity,
    make_result,
    response_fingerprint,
    safe_request,
    similarity,
    unique_token,
)

meta = {
    "name": "SQL Injection",
    "severity": "High",
    "description": "Low-impact error and boolean differential SQL injection checks with repeated baselines.",
    "category": "Injection",
}
inputs = [
    {"name": "param", "label": "Parameter", "type": "text", "required": True, "placeholder": "id"}
]

ERROR_SIGNATURES = [
    ("mysql", re.compile(r"SQL syntax.*MySQL|Warning.*mysql_|You have an error in your SQL syntax", re.I)),
    ("postgresql", re.compile(r"PostgreSQL.*ERROR|pg_query\(|unterminated quoted string", re.I)),
    ("mssql", re.compile(r"SQL Server|Unclosed quotation mark|ODBC SQL Server Driver", re.I)),
    ("oracle", re.compile(r"ORA-\d{5}|Oracle error", re.I)),
    ("sqlite", re.compile(r"SQLite/JDBCDriver|SQLite.Exception|near \".*\": syntax error", re.I)),
]

BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
]


def _error_matches(text):
    return [{"database": db, "signature": pattern.pattern} for db, pattern in ERROR_SIGNATURES if pattern.search(text)]


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
    requests_made = 0
    observations = []
    try:
        requests_made += 1
        benign_a = safe_request("GET", append_query_param(url, param, unique_token("base")))
        requests_made += 1
        benign_b = safe_request("GET", append_query_param(url, param, unique_token("base")))
        baseline_a = body_text(benign_a)
        baseline_b = body_text(benign_b)
        baseline_stability = similarity(baseline_a, baseline_b)
        baseline_errors = _error_matches(baseline_a + "\n" + baseline_b)
        baseline_summary = {
            "status_codes": [benign_a.status_code, benign_b.status_code],
            "fingerprints": [response_fingerprint(benign_a), response_fingerprint(benign_b)],
            "stability": round(baseline_stability, 3),
        }

        for payload in ("'", '"', "')"):
            requests_made += 1
            response = safe_request("GET", append_query_param(url, param, payload))
            new_errors = [item for item in _error_matches(body_text(response)) if item not in baseline_errors]
            if new_errors:
                observations.append({
                    "type": "database_error",
                    "payload": payload,
                    "severity": "High",
                    "classification_reason": "A database-specific error appeared only after an injection probe.",
                    "status_code": response.status_code,
                    "test_status": response.status_code,
                    "test_fingerprint": response_fingerprint(response),
                    "matches": new_errors,
                    "final_decision": "confirmed_database_error",
                })
                break

        # Differential checks are only meaningful when two benign responses are stable.
        if baseline_stability >= 0.90:
            for true_payload, false_payload in BOOLEAN_PAIRS:
                requests_made += 1
                true_response = safe_request("GET", append_query_param(url, param, true_payload))
                requests_made += 1
                false_response = safe_request("GET", append_query_param(url, param, false_payload))
                true_body = body_text(true_response)
                false_body = body_text(false_response)
                true_to_base = max(similarity(true_body, baseline_a), similarity(true_body, baseline_b))
                false_to_base = max(similarity(false_body, baseline_a), similarity(false_body, baseline_b))
                pair_similarity = similarity(true_body, false_body)
                status_diverged = true_response.status_code != false_response.status_code
                if (true_to_base >= 0.88 and false_to_base <= 0.70 and pair_similarity <= 0.72) or (
                    status_diverged and true_response.status_code < 400 <= false_response.status_code
                ):
                    observations.append({
                        "type": "boolean_differential",
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "severity": "High",
                        "baseline_stability": round(baseline_stability, 3),
                        "true_to_baseline": round(true_to_base, 3),
                        "false_to_baseline": round(false_to_base, 3),
                        "true_false_similarity": round(pair_similarity, 3),
                        "status_codes": [true_response.status_code, false_response.status_code],
                        "test_status": {"true": true_response.status_code, "false": false_response.status_code},
                        "fingerprints": {"true": response_fingerprint(true_response), "false": response_fingerprint(false_response)},
                        "classification_reason": "True and false probes produced a stable response differential without database-specific errors.",
                        "final_decision": "potential_boolean_differential",
                    })
                    break

        database_errors = [item for item in observations if item["type"] == "database_error"]
        boolean_differentials = [item for item in observations if item["type"] == "boolean_differential"]

        if database_errors:
            return make_result(
                True,
                "SQL injection was confirmed by a new database-specific error that was absent from stable baseline responses.",
                severity=highest_severity(item["severity"] for item in observations),
                confidence="High",
                status="confirmed",
                evidence={
                    "classification": "confirmed",
                    "classification_reason": "A database-specific error appeared only after an injection probe.",
                    "baseline_stability": round(baseline_stability, 3),
                    "baseline_summary": baseline_summary,
                    "database_errors": database_errors,
                    "boolean_differentials": boolean_differentials,
                    "final_decision": "confirmed_database_error",
                },
                recommendation="Use parameterized queries, avoid SQL string concatenation, and apply server-side type validation.",
                endpoint=url,
                parameter=param,
                cwe="CWE-89",
                cvss=9.8,
                requests_made=requests_made,
            )

        if boolean_differentials:
            return make_result(
                True,
                "A stable boolean response differential was observed. This is a potential SQL injection indicator requiring manual confirmation.",
                severity="High",
                confidence="Medium",
                status="potential",
                evidence={
                    "classification": "potential",
                    "classification_reason": "True and false probes produced a repeatable differential, but no database-specific error was observed.",
                    "baseline_stability": round(baseline_stability, 3),
                    "baseline_summary": baseline_summary,
                    "boolean_differentials": boolean_differentials,
                    "final_decision": "potential_boolean_differential",
                },
                recommendation="Manually validate the differential, then use parameterized queries and server-side type validation.",
                endpoint=url,
                parameter=param,
                cwe="CWE-89",
                cvss=9.8,
                requests_made=requests_made,
            )

        status = "inconclusive" if baseline_stability < 0.90 else "not_vulnerable"
        message = (
            "The endpoint response was too dynamic for a reliable boolean comparison; no database error was observed."
            if status == "inconclusive"
            else "No reliable SQL injection indicator was detected."
        )
        return make_result(
            False,
            message,
            severity="Info",
            confidence="Low" if status == "inconclusive" else "Medium",
            status=status,
            evidence={
                "baseline_stability": round(baseline_stability, 3),
                "baseline_summary": baseline_summary,
                "classification_reason": "No new database-specific error or reliable boolean differential was observed.",
                "final_decision": "dynamic_baseline_inconclusive" if status == "inconclusive" else "no_sql_injection_indicator",
            },
            endpoint=url,
            parameter=param,
            cwe="CWE-89",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"SQL-injection check failed: {exc}", endpoint=url, parameter=param, requests_made=requests_made)
