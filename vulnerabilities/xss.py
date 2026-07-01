import html as html_lib
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode

from bs4 import BeautifulSoup

from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
from vulnerabilities.common import (
    body_text,
    error_result,
    make_result,
    safe_request,
    unique_token,
)

meta = {
    "name": "Reflected XSS",
    "severity": "High",
    "description": "Detects reflected XSS in HTML, script, event-handler, and URL contexts.",
    "category": "Injection",
}

inputs = [
    {
        "name": "param",
        "label": "Parameter",
        "type": "text",
        "required": False,
        "placeholder": "search",
    }
]


INERT_CONTEXTS = ["textarea", "title", "style", "xmp", "noscript", "template"]


def set_query_param(url, name, value):
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)

    # Replace existing parameter instead of appending duplicate values.
    query = [(k, v) for k, v in query if k != name]
    query.append((name, value))

    path = parts.path or "/"

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            path,
            urlencode(query, doseq=True),
            parts.fragment,
        )
    )


def get_query_param_names(url):
    parts = urlsplit(url)
    return list(dict(parse_qsl(parts.query, keep_blank_values=True)).keys())


def attr_to_text(value):
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value)


def has_inert_parent(tag):
    return tag.find_parent(INERT_CONTEXTS) is not None


def looks_like_html(content_type, body):
    content_type = (content_type or "").lower()
    sample = (body or "")[:700].lower()

    return (
        "html" in content_type
        or "<html" in sample
        or "<!doctype html" in sample
        or "<body" in sample
        or "<script" in sample
        or "<form" in sample
    )


def build_payloads(token):
    js = f"window.__cyberscan_probe='{token}'"

    return [
        {
            "name": "script_tag",
            "payload": f"<script>{js}</script>",
            "context": "HTML script tag injection",
        },
        {
            "name": "img_onerror",
            "payload": f'"><img src=x onerror="{js}">',
            "context": "Attribute breakout into img onerror",
        },
        {
            "name": "svg_onload",
            "payload": f'"><svg onload="{js}"></svg>',
            "context": "Attribute breakout into svg onload",
        },
        {
            "name": "textarea_breakout",
            "payload": f"</textarea><script>{js}</script>",
            "context": "Textarea breakout",
        },
        {
            "name": "title_breakout",
            "payload": f"</title><script>{js}</script>",
            "context": "Title breakout",
        },
        {
            "name": "js_single_quote_breakout",
            "payload": f"';{js}//",
            "context": "JavaScript single quote string breakout",
        },
        {
            "name": "js_double_quote_breakout",
            "payload": f'";{js}//',
            "context": "JavaScript double quote string breakout",
        },
        {
            "name": "javascript_href",
            "payload": f"javascript:{js}",
            "context": "javascript: URL injection",
        },
    ]


def detect_executable_context(body, content_type, token, reflected_value=None):
    raw_body = body or ""
    decoded_body = html_lib.unescape(raw_body)
    reflected_value = token if reflected_value is None else reflected_value

    js_marker = "window.__cyberscan_probe"

    detection = {
        "reflected_raw": reflected_value in raw_body,
        "reflected_decoded": reflected_value in decoded_body,
        "executable_context_confirmed": False,
        "token_reflected_raw": token in raw_body,
        "token_reflected_decoded": token in decoded_body,
        "js_marker_reflected_raw": js_marker in raw_body,
        "js_marker_reflected_decoded": js_marker in decoded_body,
        "executable_context": None,
        "tag": None,
        "attribute": None,
        "inert_html_context": False,
    }

    if not looks_like_html(content_type, raw_body):
        return False, detection

    # Decoded text is reflection evidence only. Executable evidence must come
    # from tags and attributes parsed directly from the raw HTTP response.
    soup = BeautifulSoup(raw_body, "html.parser")

    # 1) <script>window.__cyberscan_probe='TOKEN'</script>
    for script in soup.find_all("script"):
        script_text = script.get_text("", strip=False)

        if js_marker in script_text and token in script_text:
            inert = has_inert_parent(script)

            detection.update(
                {
                    "executable_context": "script_element",
                    "tag": "script",
                    "attribute": None,
                    "inert_html_context": inert,
                    "executable_context_confirmed": not inert,
                }
            )

            if not inert:
                return True, detection

    # 2) Event handlers: onerror, onload, onfocus, ...
    for tag in soup.find_all(True):
        if has_inert_parent(tag):
            continue

        for attr_name, attr_value in tag.attrs.items():
            attr_name_lower = attr_name.lower()
            attr_value_text = attr_to_text(attr_value)

            if (
                attr_name_lower.startswith("on")
                and js_marker in attr_value_text
                and token in attr_value_text
            ):
                detection.update(
                    {
                        "executable_context": "event_handler_attribute",
                        "tag": tag.name,
                        "attribute": attr_name,
                        "inert_html_context": False,
                        "executable_context_confirmed": True,
                    }
                )
                return True, detection

    # 3) javascript: URL
    url_attrs = {"href", "src", "xlink:href", "formaction"}

    for tag in soup.find_all(True):
        if has_inert_parent(tag):
            continue

        for attr_name, attr_value in tag.attrs.items():
            attr_name_lower = attr_name.lower()
            attr_value_text = attr_to_text(attr_value).strip()
            parsed_attr = attr_value_text.lower()

            if (
                attr_name_lower in url_attrs
                and parsed_attr.startswith("javascript:")
                and js_marker in attr_value_text
                and token in attr_value_text
            ):
                detection.update(
                    {
                        "executable_context": "javascript_url",
                        "tag": tag.name,
                        "attribute": attr_name,
                        "inert_html_context": False,
                        "executable_context_confirmed": True,
                    }
                )
                return True, detection

    return False, detection


def discover_get_form_targets(url):
    """
    Finds GET forms such as:
    <form method="GET">
        <input name="search">
    </form>

    This is important for PortSwigger labs because the vulnerable parameter
    is usually discovered from the search form.
    """
    response = safe_request("GET", url)
    content_type = response.headers.get("Content-Type", "")
    body = body_text(response)

    targets = []

    if not looks_like_html(content_type, body):
        return targets, response

    soup = BeautifulSoup(body, "html.parser")

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()

        if method != "get":
            continue

        action = form.get("action") or response.url
        action_url = urljoin(response.url, action)

        fields = []

        for control in form.find_all(["input", "textarea", "select"]):
            name = control.get("name")

            if not name:
                continue

            input_type = (control.get("type") or "text").lower()

            if input_type in {"submit", "button", "reset", "file", "image"}:
                continue

            value = control.get("value", "")
            action_url = set_query_param(action_url, name, value)

            if input_type in {"text", "search", "url", "email"} or control.name in {
                "textarea",
                "select",
            }:
                fields.append(name)

        for field in fields:
            targets.append(
                {
                    "url": action_url,
                    "param": field,
                    "source": "discovered_get_form",
                }
            )

    return targets, response


def add_unique_target(targets, seen, target_url, param, source):
    if not param:
        return

    key = (target_url, param)

    if key in seen:
        return

    seen.add(key)
    targets.append(
        {
            "url": target_url,
            "param": param,
            "source": source,
        }
    )


def scan(url, param=""):
    token = unique_token("xss")
    payloads = build_payloads(token)

    requests_made = 0
    attempts = []
    targets = []
    seen_targets = set()
    last_endpoint = url

    try:
        # 1) Manual param from UI, example: search
        if param:
            add_unique_target(targets, seen_targets, url, param, "manual_input")

        # 2) Existing query params from URL, example: /?search=h
        for query_param in get_query_param_names(url):
            add_unique_target(targets, seen_targets, url, query_param, "url_query")

        # 3) Discover GET forms if no param was provided/found
        if not targets:
            requests_made += 1
            discovered_targets, discovery_response = discover_get_form_targets(url)

            for item in discovered_targets:
                add_unique_target(
                    targets,
                    seen_targets,
                    item["url"],
                    item["param"],
                    item["source"],
                )

        # 4) Smart fallback for common search parameters
        if not targets:
            for common_param in ["search", "q", "query", "s", "keyword"]:
                add_unique_target(
                    targets,
                    seen_targets,
                    url,
                    common_param,
                    "common_param_fallback",
                )

        if not targets:
            return make_result(
                False,
                "No GET parameter or search form was found to test.",
                status="inconclusive",
                severity="Info",
                confidence="Low",
                evidence={
                    "target": url,
                    "hint": "Try scanning a URL like /?search=test or enter parameter name: search",
                },
                endpoint=url,
                requests_made=requests_made,
            )

        for target in targets:
            target_url = target["url"]
            target_param = target["param"]

            baseline_url = set_query_param(target_url, target_param, token)
            requests_made += 1
            baseline = safe_request("GET", baseline_url)

            baseline_body = body_text(baseline)
            baseline_content_type = baseline.headers.get("Content-Type", "")

            baseline_confirmed, baseline_detection = detect_executable_context(
                baseline_body,
                baseline_content_type,
                token,
                token,
            )

            for payload_info in payloads:
                payload_name = payload_info["name"]
                payload = payload_info["payload"]

                test_url = set_query_param(target_url, target_param, payload)
                requests_made += 1
                response = safe_request("GET", test_url)
                last_endpoint = response.url

                content_type = response.headers.get("Content-Type", "")
                body = body_text(response)
                decoded_body = html_lib.unescape(body)

                confirmed, detection = detect_executable_context(
                    body,
                    content_type,
                    token,
                    payload,
                )

                attempt = {
                    "target_source": target["source"],
                    "tested_url": response.url,
                    "parameter": target_param,
                    "payload_name": payload_name,
                    "context_tested": payload_info["context"],
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "reflected_raw": detection["reflected_raw"],
                    "reflected_decoded": detection["reflected_decoded"],
                    "executable_context_confirmed": confirmed,
                    "token_reflected_raw": token in body,
                    "token_reflected_decoded": token in decoded_body,
                    "payload_reflected_raw": payload in body,
                    "payload_reflected_decoded": payload in decoded_body,
                    "confirmed_executable_context": confirmed,
                    "final_decision": "executable_context_confirmed" if confirmed else "no_executable_context_confirmed",
                    "detection": detection,
                }

                attempts.append(attempt)

                if confirmed and not baseline_confirmed:
                    evidence = {
                        "parameter": target_param,
                        "token": token,
                        "target_source": target["source"],
                        "baseline_url": baseline.url,
                        "confirmed_url": response.url,
                        "confirmed_payload": payload_name,
                        "confirmed_context": payload_info["context"],
                        "final_decision": "executable_context_confirmed",
                        "baseline_detection": baseline_detection,
                        "detection": detection,
                        "attempts": attempts,
                    }

                    return make_result(
                        True,
                        "Reflected XSS confirmed. The probe was reflected into an executable HTML/JavaScript context.",
                        severity="High",
                        confidence="High",
                        evidence=evidence,
                        recommendation=(
                            "Apply context-aware output encoding, escape user input before inserting it into HTML, "
                            "avoid direct insertion into JavaScript contexts, and use a restrictive Content Security Policy."
                        ),
                        endpoint=response.url,
                        parameter=target_param,
                        cwe="CWE-79",
                        cvss=8.2,
                        requests_made=requests_made,
                    )

        any_reflection = any(
            item["token_reflected_raw"] or item["token_reflected_decoded"]
            for item in attempts
        )

        message = (
            "Input reflection was detected, but executable XSS was not confirmed."
            if any_reflection
            else "Reflected XSS was not confirmed. The tested payloads were not reflected."
        )

        return make_result(
            False,
            message,
            severity="Info",
            confidence="Medium",
            evidence={
                "tested_targets": targets,
                "token": token,
                "final_decision": "reflected_non_executable" if any_reflection else "no_reflection_detected",
                "attempts": attempts,
            },
            endpoint=last_endpoint,
            parameter=targets[0]["param"] if targets else param,
            cwe="CWE-79",
            requests_made=requests_made,
        )

    except (ScanCancelled, RequestBudgetExceeded):
        raise

    except Exception as exc:
        return error_result(
            f"Reflected-XSS check failed: {exc}",
            endpoint=url,
            parameter=param,
            requests_made=requests_made,
        )
