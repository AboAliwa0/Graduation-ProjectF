from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

SENSITIVE_KEY_RE = re.compile(r"(authorization|cookie|token|secret|password|api[-_]?key|session)", re.I)


class AuthProfileError(ValueError):
    pass


def _clean_mapping(value: Any, *, label: str, max_items: int = 40) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AuthProfileError(f"{label} must be a JSON object.") from exc
    if not isinstance(value, dict):
        raise AuthProfileError(f"{label} must be a JSON object.")
    if len(value) > max_items:
        raise AuthProfileError(f"{label} contains too many entries.")
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip()
        item = str(raw_value).strip()
        if not key or len(key) > 128 or len(item) > 8192:
            raise AuthProfileError(f"{label} contains an invalid key or value.")
        if any(ch in key or ch in item for ch in ("\r", "\n", "\x00")):
            raise AuthProfileError(f"{label} cannot contain control characters.")
        result[key] = item
    return result


def _validate_storage_state(value: Any) -> dict[str, Any] | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AuthProfileError("Browser storage state must be a JSON object.") from exc
    if not isinstance(value, dict):
        raise AuthProfileError("Browser storage state must be a JSON object.")
    cookies = value.get("cookies", [])
    origins = value.get("origins", [])
    if not isinstance(cookies, list) or not isinstance(origins, list):
        raise AuthProfileError("Browser storage state must contain cookie and origin lists.")
    if len(cookies) > 200 or len(origins) > 100:
        raise AuthProfileError("Browser storage state is too large.")
    encoded = json.dumps(value, ensure_ascii=False)
    if len(encoded) > 512_000:
        raise AuthProfileError("Browser storage state exceeds the 500 KB limit.")
    return value


@dataclass(slots=True)
class AuthProfile:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    storage_state: dict[str, Any] | None = None
    expected_access: str = "unknown"

    def to_runtime_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "storage_state": self.storage_state,
            "expected_access": self.expected_access,
        }

    def safe_summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "header_names": sorted(self.headers),
            "cookie_names": sorted(self.cookies),
            "has_storage_state": self.storage_state is not None,
            "expected_access": self.expected_access,
        }


def parse_browser_storage_state(value: Any) -> dict[str, Any] | None:
    return _validate_storage_state(value)


def parse_auth_profiles(value: Any, *, max_profiles: int = 4) -> list[AuthProfile]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AuthProfileError("Auth profiles must be a JSON array.") from exc
    if not isinstance(value, list):
        raise AuthProfileError("Auth profiles must be a JSON array.")
    if len(value) > max_profiles:
        raise AuthProfileError(f"At most {max_profiles} auth profiles are allowed.")
    profiles: list[AuthProfile] = []
    names: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise AuthProfileError(f"Auth profile #{index + 1} must be an object.")
        name = str(raw.get("name") or f"profile-{index + 1}").strip()[:80]
        if not name or name.lower() in names:
            raise AuthProfileError("Auth profile names must be non-empty and unique.")
        names.add(name.lower())
        expected_access = str(raw.get("expected_access") or "unknown").strip().lower()
        if expected_access not in {"low", "high", "admin", "user", "anonymous", "unknown"}:
            raise AuthProfileError(f"Unsupported expected_access value for {name}.")
        profiles.append(
            AuthProfile(
                name=name,
                headers=_clean_mapping(raw.get("headers"), label=f"Headers for {name}"),
                cookies=_clean_mapping(raw.get("cookies"), label=f"Cookies for {name}"),
                storage_state=_validate_storage_state(raw.get("storage_state")),
                expected_access=expected_access,
            )
        )
    return profiles


def redact_mapping(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if SENSITIVE_KEY_RE.search(str(key)):
                redacted[str(key)] = "<redacted>"
            else:
                redacted[str(key)] = redact_mapping(item)
        return redacted
    if isinstance(value, list):
        return [redact_mapping(item) for item in value[:200]]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "…"
    return value
