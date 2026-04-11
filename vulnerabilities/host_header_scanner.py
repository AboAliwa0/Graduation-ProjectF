from utils import get_session, rate_sleep
from report import section, vuln, safe, log


def check_host_header(url):
    section("Host Header Injection")
    session    = get_session()
    vulnerable = False
    evil_host  = "evil.com"

    test_headers = [
        {"Host":              evil_host},
        {"X-Forwarded-Host":  evil_host},
        {"X-Host":            evil_host},
        {"X-Forwarded-Server": evil_host},
        {"Forwarded":         f"for=127.0.0.1;host={evil_host}"},
    ]

    # Baseline
    try:
        rate_sleep()
        normal   = session.get(url, timeout=10)
        base_len = len(normal.text)
        log(f"[*] Baseline response length: {base_len}")
    except Exception as e:
        log(f"[!] Error establishing baseline: {e}")
        return

    for headers in test_headers:
        header_name = list(headers.keys())[0]
        try:
            rate_sleep()
            r           = session.get(url, headers=headers, timeout=10)
            current_len = len(r.text)
            response    = r.text

            log(f"[*] Testing {header_name:25} -> Length: {current_len}")

            if evil_host in response:
                vuln(
                    f"Host Header reflected in response via [{header_name}]",
                    "HIGH",
                    verify_cmd=f'curl -H "{header_name}: {evil_host}" {url}'
                )
                vulnerable = True
                continue

            poisoned = [
                f"href=\"http://{evil_host}",
                f"href='http://{evil_host}",
                f"action=\"http://{evil_host}",
                f"url=http://{evil_host}",
            ]
            if any(p in response for p in poisoned):
                vuln(
                    f"Host Header Injection - Poisoned link via [{header_name}]",
                    "HIGH",
                    verify_cmd=f'curl -H "{header_name}: {evil_host}" {url}'
                )
                vulnerable = True
                continue

            if abs(current_len - base_len) > 50:
                vuln(
                    f"Possible Host Header Injection - Response changed via [{header_name}]",
                    "MEDIUM",
                    verify_cmd=f'curl -H "{header_name}: {evil_host}" {url}'
                )
                vulnerable = True

        except Exception as e:
            log(f"[-] Error testing {header_name}: {e}")

    if not vulnerable:
        safe("No Host Header issues detected with common headers")
