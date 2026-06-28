from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import time

from vulnerabilities.common import error_result, make_result, safe_request

meta = {
    "name": "Generic Rate-Limit Observation",
    "severity": "Low",
    "description": "Observes five low-impact requests for explicit throttling signals; absence is reported only as informational/potential.",
    "category": "Availability",
}
inputs = []


def scan(url):
    observations = []
    try:
        for index in range(5):
            started = time.perf_counter()
            response = safe_request("GET", url, allow_redirects=False)
            observations.append({
                "attempt": index + 1,
                "status": response.status_code,
                "retry_after": response.headers.get("Retry-After", ""),
                "elapsed": round(time.perf_counter() - started, 3),
            })
            if response.status_code == 429 or response.headers.get("Retry-After"):
                break
            time.sleep(0.08)

        protected = any(item["status"] == 429 or item["retry_after"] for item in observations)
        if protected:
            return make_result(
                False,
                "Explicit rate-limit behavior was observed.",
                severity="Info",
                confidence="High",
                evidence={"attempts": observations},
                endpoint=url,
                cwe="CWE-770",
                requests_made=len(observations),
            )
        return make_result(
            True,
            "No explicit throttling signal appeared during five requests. Public GET endpoints may legitimately allow this rate.",
            severity="Low",
            confidence="Low",
            status="potential",
            evidence={"attempts": observations},
            recommendation="Apply endpoint-specific limits to expensive or sensitive operations and monitor abusive patterns.",
            endpoint=url,
            cwe="CWE-770",
            cvss=3.1,
            requests_made=len(observations),
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Rate-limit observation failed: {exc}", endpoint=url, requests_made=len(observations))
