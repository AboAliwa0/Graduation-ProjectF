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
    requests_made = 0
    try:
        for index in range(5):
            started = time.perf_counter()
            requests_made += 1
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
        progressive_delay = False
        if len(observations) >= 3:
            elapsed = [item["elapsed"] for item in observations]
            progressive_delay = any(
                window[0] < window[1] < window[2] and window[2] - window[0] >= 0.12
                for window in zip(elapsed, elapsed[1:], elapsed[2:])
            )
        evidence = {
            "attempts": observations,
            "status_codes": [item["status"] for item in observations],
            "timings": [item["elapsed"] for item in observations],
            "retry_after": [item["retry_after"] for item in observations if item["retry_after"]],
            "attempt_count": len(observations),
            "progressive_delay_observed": progressive_delay,
            "conclusion": "explicit_or_delay_throttling_observed" if protected or progressive_delay else "no_explicit_throttling_observed",
        }
        if protected or progressive_delay:
            return make_result(
                False,
                "Explicit rate-limit behavior was observed.",
                severity="Info",
                confidence="High",
                evidence=evidence,
                endpoint=url,
                cwe="CWE-770",
                requests_made=requests_made,
            )
        return make_result(
            True,
            "No explicit throttling signal appeared during five requests. Public GET endpoints may legitimately allow this rate.",
            severity="Low",
            confidence="Low",
            status="potential",
            evidence=evidence,
            recommendation="Apply endpoint-specific limits to expensive or sensitive operations and monitor abusive patterns.",
            endpoint=url,
            cwe="CWE-770",
            cvss=3.1,
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Rate-limit observation failed: {exc}", endpoint=url, requests_made=requests_made)
