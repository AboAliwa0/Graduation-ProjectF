from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from services.scan_runtime import current_runtime

DEFAULT_TIMEOUT = float(os.getenv("SCANNER_TIMEOUT", "8"))
MAX_REDIRECTS = int(os.getenv("SCANNER_MAX_REDIRECTS", "3"))
MAX_RESPONSE_BYTES = int(os.getenv("SCANNER_MAX_RESPONSE_BYTES", str(2 * 1024 * 1024)))
USER_AGENT = os.getenv("SCANNER_USER_AGENT", "CyberScan/5.0 Authorized-Security-Assessment")


class UnsafeTargetError(ValueError):
    pass


@dataclass(slots=True)
class Result:
    vulnerable: bool
    result: str
    severity: str = "Info"
    confidence: str = "Low"
    status: str = "not_vulnerable"
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    endpoint: str = ""
    parameter: str = ""
    cwe: str = ""
    cvss: float = 0.0
    requests_made: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_result(
    vulnerable: bool,
    message: str,
    *,
    severity: str = "Info",
    confidence: str = "Low",
    status: str | None = None,
    evidence: dict[str, Any] | None = None,
    recommendation: str = "",
    endpoint: str = "",
    parameter: str = "",
    cwe: str = "",
    cvss: float = 0.0,
    requests_made: int = 0,
) -> dict[str, Any]:
    if status is None:
        status = "confirmed" if vulnerable else "not_vulnerable"
    return Result(
        vulnerable=vulnerable,
        result=message,
        severity=severity,
        confidence=confidence,
        status=status,
        evidence=evidence or {},
        recommendation=recommendation,
        endpoint=endpoint,
        parameter=parameter,
        cwe=cwe,
        cvss=cvss,
        requests_made=requests_made,
    ).to_dict()


def inconclusive(message: str, **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("severity", "Info")
    kwargs.setdefault("confidence", "Low")
    kwargs["status"] = "inconclusive"
    return make_result(False, message, **kwargs)


def error_result(message: str, **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("severity", "Info")
    kwargs.setdefault("confidence", "Low")
    kwargs["status"] = "error"
    return make_result(False, message, **kwargs)


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _host_addresses(hostname: str) -> set[ipaddress._BaseAddress]:
    addresses: set[ipaddress._BaseAddress] = set()
    try:
        addresses.add(ipaddress.ip_address(hostname))
        return addresses
    except ValueError:
        pass

    for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
        addresses.add(ipaddress.ip_address(item[4][0]))
    return addresses


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def validate_target_url(url: str, *, allow_private: bool | None = None) -> str:
    value = (url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTargetError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise UnsafeTargetError("Target URL must contain a hostname.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("Credentials embedded in target URLs are not allowed.")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise UnsafeTargetError("Target URL contains an invalid port.")

    runtime = current_runtime()
    if allow_private is None and runtime is not None:
        allow_private = runtime.allow_private
    if allow_private is None:
        allow_private = env_bool("ALLOW_PRIVATE_TARGETS", False)

    try:
        addresses = _host_addresses(parsed.hostname)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"Target hostname could not be resolved: {exc}") from exc

    if not addresses:
        raise UnsafeTargetError("Target hostname did not resolve to an IP address.")
    if not allow_private and any(_is_blocked_ip(ip) for ip in addresses):
        raise UnsafeTargetError(
            "Private, loopback, link-local, reserved, and metadata-network targets are blocked. "
            "Enable ALLOW_PRIVATE_TARGETS only inside an isolated lab."
        )
    return value


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _merge_headers(runtime_headers: dict[str, str], supplied: dict[str, Any]) -> dict[str, str]:
    merged = {str(key): str(value) for key, value in runtime_headers.items() if value is not None}
    merged.update({str(key): str(value) for key, value in supplied.items() if value is not None})
    merged.setdefault("User-Agent", USER_AGENT)
    # Host is generated by the HTTP library. Supplying it through the global auth
    # context is dangerous and unnecessary; dedicated Host-header checks set it per request.
    if "Host" in merged and not supplied.get("Host"):
        merged.pop("Host", None)
    return merged


def safe_request(
    method: str,
    url: str,
    *,
    session: requests.Session | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = False,
    max_redirects: int = MAX_REDIRECTS,
    allow_private: bool | None = None,
    **kwargs: Any,
) -> requests.Response:
    runtime = current_runtime()
    if allow_private is None and runtime is not None:
        allow_private = runtime.allow_private
    current = validate_target_url(url, allow_private=allow_private)

    own_session = False
    if session is not None:
        sess = session
    elif runtime is not None:
        sess = runtime.session
    else:
        sess = requests.Session()
        sess.trust_env = False
        own_session = True

    supplied_headers = dict(kwargs.pop("headers", {}) or {})
    runtime_headers = runtime.default_headers if runtime is not None else {}
    headers = _merge_headers(runtime_headers, supplied_headers)
    verify_tls = kwargs.pop("verify", runtime.verify_tls if runtime is not None else True)
    original_origin = _origin(current)

    try:
        for hop in range(max_redirects + 1):
            if runtime is not None:
                runtime.before_request()

            response = sess.request(
                method=method.upper(),
                url=current,
                timeout=timeout,
                allow_redirects=False,
                headers=headers,
                verify=verify_tls,
                stream=True,
                **kwargs,
            )
            content = response.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True)
            truncated = len(content) > MAX_RESPONSE_BYTES
            response._content = content[:MAX_RESPONSE_BYTES]
            response._content_consumed = True
            response.close()
            if truncated:
                response.headers["X-CyberScan-Body-Truncated"] = "true"

            if not allow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
                return response

            location = response.headers.get("Location")
            if not location:
                return response
            if hop >= max_redirects:
                raise requests.TooManyRedirects(f"More than {max_redirects} redirects")
            next_url = urljoin(current, location)
            validate_target_url(next_url, allow_private=allow_private)

            # Never forward ambient credentials to a different origin.
            if _origin(next_url) != original_origin:
                for sensitive in ("Authorization", "Proxy-Authorization", "Cookie"):
                    headers.pop(sensitive, None)

            current = next_url
            if response.status_code == 303 or (response.status_code in {301, 302} and method.upper() == "POST"):
                method = "GET"
                kwargs.pop("data", None)
                kwargs.pop("json", None)
        return response
    finally:
        if own_session:
            sess.close()


def append_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, val) for key, val in query if key != name]
    query.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def replace_path_token(template: str, token: str, value: str) -> str:
    return template.replace("{" + token + "}", value)


def body_text(response: requests.Response) -> str:
    content_type = response.headers.get("Content-Type", "").lower()
    if not any(kind in content_type for kind in ("text/", "json", "xml", "javascript", "html")):
        return ""
    try:
        return response.text
    except Exception:
        return response.content.decode("utf-8", errors="replace")


def normalized_text(text: str) -> str:
    value = re.sub(r"\b\d{4,}\b", "<NUM>", text or "")
    value = re.sub(r"[0-9a-f]{16,}", "<HEX>", value, flags=re.I)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, normalized_text(left), normalized_text(right)).ratio()


def response_fingerprint(response: requests.Response) -> dict[str, Any]:
    text = normalized_text(body_text(response))
    return {
        "status": response.status_code,
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest(),
        "content_type": response.headers.get("Content-Type", ""),
        "truncated": response.headers.get("X-CyberScan-Body-Truncated") == "true",
    }


def unique_token(prefix: str = "cs") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def highest_severity(values: Iterable[str]) -> str:
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return max(values, key=lambda item: order.get(item, 0), default="Info")


def timed_request(*args: Any, **kwargs: Any) -> tuple[requests.Response, float]:
    started = time.perf_counter()
    response = safe_request(*args, **kwargs)
    return response, time.perf_counter() - started
