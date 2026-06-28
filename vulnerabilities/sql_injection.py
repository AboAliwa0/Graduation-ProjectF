from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import re

from vulnerabilities.common import (
    append_query_param,
    body_text,
    error_result,
    highest_severity,
    make_result,
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
        return make_result(False, "A parameter name is required.", status="inconclusive", endpoint=url)
    requests_made = 0
    observations = []
    try:
        benign_a = safe_request("GET", append_query_param(url, param, unique_token("base")))
        benign_b = safe_request("GET", append_query_param(url, param, unique_token("base")))
        requests_made += 2
        baseline_a = body_text(benign_a)
        baseline_b = body_text(benign_b)
        baseline_stability = similarity(baseline_a, baseline_b)
        baseline_errors = _error_matches(baseline_a + "\n" + baseline_b)

        for payload in ("'", '"', "')"):
            response = safe_request("GET", append_query_param(url, param, payload))
            requests_made += 1
            new_errors = [item for item in _error_matches(body_text(response)) if item not in baseline_errors]
            if new_errors:
                observations.append({
                    "type": "database_error",
                    "payload": payload,
                    "severity": "High",
                    "status_code": response.status_code,
                    "matches": new_errors,
                })
                break

        # Differential checks are only meaningful when two benign responses are stable.
        if baseline_stability >= 0.90:
            for true_payload, false_payload in BOOLEAN_PAIRS:
                true_response = safe_request("GET", append_query_param(url, param, true_payload))
                false_response = safe_request("GET", append_query_param(url, param, false_payload))
                requests_made += 2
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
                    })
                    break

        if observations:
            confidence = "High" if any(item["type"] == "database_error" for item in observations) else "Medium"
            return make_result(
                True,
                "SQL injection indicators were confirmed by a database error or a stable boolean differential.",
                severity=highest_severity(item["severity"] for item in observations),
                confidence=confidence,
                evidence={"baseline_stability": round(baseline_stability, 3), "observations": observations},
                recommendation="Use parameterized queries, avoid SQL string concatenation, and apply server-side type validation.",
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
            evidence={"baseline_stability": round(baseline_stability, 3)},
            endpoint=url,
            parameter=param,
            cwe="CWE-89",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"SQL-injection check failed: {exc}", endpoint=url, parameter=param, requests_made=requests_made)
