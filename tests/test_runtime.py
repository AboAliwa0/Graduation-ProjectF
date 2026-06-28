import json

import pytest

from services.scan_runtime import (
    RequestBudgetExceeded,
    ScanCancelled,
    ScanRuntime,
    activate_runtime,
)
from vulnerabilities.common import MAX_RESPONSE_BYTES, safe_request


def test_runtime_applies_in_memory_auth_and_counts_requests(lab_server):
    runtime = ScanRuntime(
        scan_id=1,
        user_id=1,
        request_budget=3,
        default_headers={"Authorization": "Bearer authorized-test", "X-Test-Header": "present"},
        cookies={"session": "lab-session"},
        allow_private=True,
    )
    with activate_runtime(runtime):
        response = safe_request("GET", lab_server + "/echo-auth")
    payload = response.json()
    assert payload["authorization"] == "Bearer authorized-test"
    assert payload["custom"] == "present"
    assert "session=lab-session" in payload["cookie"]
    assert runtime.request_count == 1


def test_runtime_enforces_request_budget(lab_server):
    runtime = ScanRuntime(scan_id=2, user_id=1, request_budget=1, allow_private=True)
    with activate_runtime(runtime):
        safe_request("GET", lab_server + "/safe/headers")
        with pytest.raises(RequestBudgetExceeded):
            safe_request("GET", lab_server + "/safe/headers")
    assert runtime.request_count == 1


def test_runtime_honors_cancellation_before_network_call(lab_server):
    runtime = ScanRuntime(scan_id=3, user_id=1, request_budget=2, allow_private=True)
    runtime.cancel()
    with activate_runtime(runtime):
        with pytest.raises(ScanCancelled):
            safe_request("GET", lab_server + "/safe/headers")
    assert runtime.request_count == 0


def test_response_body_is_stream_limited(lab_server):
    response = safe_request("GET", lab_server + "/large", allow_private=True)
    assert len(response.content) == MAX_RESPONSE_BYTES
    assert response.headers["X-CyberScan-Body-Truncated"] == "true"
