from services.scan_runtime import RequestBudgetExceeded, ScanCancelled
import re

from vulnerabilities.common import (
    UnsafeTargetError,
    body_text,
    error_result,
    inconclusive,
    make_result,
    resolve_same_origin_url,
    safe_request,
    sanitize_url,
)

meta = {
    "name": "Directory Listing",
    "severity": "Medium",
    "description": "Checks a small, low-impact set of common directories for index listings.",
    "category": "Exposure",
}
inputs = [
    {
        "name": "paths",
        "label": "Paths (comma separated)",
        "type": "text",
        "required": False,
        "placeholder": "uploads/,files/,backup/",
        "help": "Optional low-impact list. Maximum 10 paths.",
    }
]

DEFAULT_PATHS = ("uploads/", "files/", "backup/", "images/", "static/")
LISTING_PATTERNS = (
    re.compile(r"<title>\s*index of\s+", re.I),
    re.compile(r"<h1>\s*index of\s+", re.I),
    re.compile(r"directory listing for", re.I),
)
TITLE_PATTERN = re.compile(r"<title>\s*(.*?)\s*</title>", re.I | re.S)


def _listing_signature(text):
    matched = [pattern.pattern for pattern in LISTING_PATTERNS if pattern.search(text)]
    return matched[0] if matched else ""


def _page_title(text):
    match = TITLE_PATTERN.search(text)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""


def scan(url, paths=""):
    selected = [item.strip() for item in str(paths or "").split(",") if item.strip()]
    selected = (selected or list(DEFAULT_PATHS))[:10]
    found = []
    checked = []
    unsafe_paths = []
    requests_made = 0
    try:
        for path in selected:
            try:
                candidate = resolve_same_origin_url(url, path)
            except UnsafeTargetError:
                unsafe_paths.append(sanitize_url(path))
                checked.append({
                    "path": sanitize_url(path),
                    "url": "",
                    "status_code": None,
                    "title": "",
                    "signature": "",
                    "link_count": 0,
                    "final_decision": "unsafe_cross_origin_path_skipped",
                })
                continue
            requests_made += 1
            response = safe_request("GET", candidate)
            text = body_text(response)
            link_count = len(re.findall(r"<a\s+[^>]*href=", text, flags=re.I))
            signature = _listing_signature(text)
            item = {
                "path": path,
                "url": response.url,
                "status_code": response.status_code,
                "title": _page_title(text),
                "signature": signature,
                "link_count": link_count,
                "final_decision": "directory_listing_confirmed" if response.status_code == 200 and link_count >= 2 and signature else "no_listing_signature",
            }
            checked.append(item)
            if response.status_code == 200 and link_count >= 2 and signature:
                found.append(item)

        if found:
            return make_result(
                True,
                f"Directory listing was confirmed on {len(found)} path(s).",
                severity="Medium",
                confidence="High",
                evidence={"listings": found, "checked_paths": checked},
                recommendation="Disable auto-indexing and restrict access to directories that should not be public.",
                endpoint=url,
                cwe="CWE-548",
                cvss=5.3,
                requests_made=requests_made,
            )
        if unsafe_paths and requests_made == 0:
            return inconclusive(
                "No directory paths were tested because every configured path left the authorized target origin.",
                evidence={
                    "tested_paths": selected,
                    "unsafe_paths": unsafe_paths,
                    "checked_paths": checked,
                    "final_decision": "no_safe_same_origin_paths",
                },
                endpoint=url,
                requests_made=0,
            )
        return make_result(
            False,
            "No directory listing signature was found in the tested paths.",
            severity="Info",
            confidence="Medium",
            evidence={
                "tested_paths": selected,
                "unsafe_paths": unsafe_paths,
                "checked_paths": checked,
                "final_decision": "no_directory_listing_confirmed",
            },
            endpoint=url,
            cwe="CWE-548",
            requests_made=requests_made,
        )
    except (ScanCancelled, RequestBudgetExceeded):
        raise
    except Exception as exc:
        return error_result(f"Directory listing check failed: {exc}", endpoint=url, requests_made=requests_made)
