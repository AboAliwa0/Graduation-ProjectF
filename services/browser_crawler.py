from __future__ import annotations

import os
import shutil
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

from services.auth_profiles import redact_mapping
from services.scan_runtime import RequestBudgetExceeded, ScanCancelled, current_runtime
from vulnerabilities.common import validate_target_url

SAFE_BROWSER_METHODS = {"GET", "HEAD", "OPTIONS"}
TRACKED_RESOURCE_TYPES = {"document", "xhr", "fetch", "websocket"}


class BrowserUnavailable(RuntimeError):
    pass


@dataclass(slots=True)
class BrowserRequestRecord:
    method: str
    url: str
    resource_type: str
    status: int | None = None
    content_type: str = ""
    same_origin: bool = True
    blocked: bool = False
    failure: str = ""


@dataclass(slots=True)
class BrowserInventory:
    start_url: str
    pages_visited: list[str] = field(default_factory=list)
    discovered_links: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    requests: list[BrowserRequestRecord] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    blocked_requests: list[dict[str, str]] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)
    title: str = ""
    final_url: str = ""
    browser: str = "chromium"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **{key: value for key, value in asdict(self).items() if key != "requests"},
            "requests": [asdict(item) for item in self.requests],
        }


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _chromium_path() -> str | None:
    configured = os.getenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", "").strip()
    if configured and os.path.exists(configured):
        return configured
    for candidate in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _framework_hints(html: str) -> list[str]:
    value = html.lower()
    hints = []
    signatures = {
        "React": ("data-reactroot", "__next_data__", "/_next/", "react"),
        "Angular": ("ng-version", "_ngcontent", "angular"),
        "Vue": ("data-v-", "__vue__", "vue"),
        "Svelte": ("svelte-", "__svelte"),
        "Nuxt": ("__nuxt__", "/_nuxt/"),
    }
    for name, tokens in signatures.items():
        if any(token in value for token in tokens):
            hints.append(name)
    return hints


def crawl_spa(
    start_url: str,
    *,
    storage_state: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    max_pages: int = 8,
    navigation_timeout_ms: int = 12_000,
    allow_state_changing: bool = False,
    allow_third_party: bool = False,
) -> BrowserInventory:
    target = validate_target_url(start_url)
    target_origin = _origin(target)
    target_host = target_origin[1]
    max_pages = max(1, min(int(max_pages), 30))
    navigation_timeout_ms = max(2_000, min(int(navigation_timeout_ms), 60_000))
    runtime = current_runtime()
    inventory = BrowserInventory(start_url=target)

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - import availability depends on install
        raise BrowserUnavailable("Playwright is not installed. Run: python -m playwright install chromium") from exc

    request_by_key: dict[tuple[str, str], BrowserRequestRecord] = {}
    fatal: Exception | None = None

    def safe_url(raw: str) -> str | None:
        try:
            parsed = urlparse(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            if not allow_third_party and (parsed.hostname or "").lower() != target_host:
                return None
            validate_target_url(raw)
            return urldefrag(raw)[0]
        except Exception:
            return None

    launch_args = ["--disable-dev-shm-usage"]
    if os.getenv("PLAYWRIGHT_DISABLE_SANDBOX", "").strip().lower() in {"1", "true", "yes", "on"} or (hasattr(os, "geteuid") and os.geteuid() == 0):
        launch_args.append("--no-sandbox")

    with sync_playwright() as playwright:
        bundled_path = getattr(playwright.chromium, "executable_path", "")
        chromium_path = None if bundled_path and os.path.exists(bundled_path) else _chromium_path()
        try:
            launch_kwargs = {"headless": True, "args": launch_args}
            if chromium_path:
                launch_kwargs["executable_path"] = chromium_path
            browser = playwright.chromium.launch(**launch_kwargs)
        except Exception as exc:
            raise BrowserUnavailable(
                "Chromium could not start. Install it with 'python -m playwright install chromium' "
                "or set PLAYWRIGHT_CHROMIUM_EXECUTABLE."
            ) from exc

        context_kwargs: dict[str, Any] = {
            "ignore_https_errors": bool(runtime and not runtime.verify_tls),
            "extra_http_headers": dict(extra_headers or {}),
            "service_workers": "block",
        }
        if storage_state:
            context_kwargs["storage_state"] = storage_state
        context = browser.new_context(**context_kwargs)
        context.set_default_navigation_timeout(navigation_timeout_ms)
        context.set_default_timeout(min(navigation_timeout_ms, 15_000))

        def route_handler(route, request) -> None:
            nonlocal fatal
            raw_url = request.url
            parsed = urlparse(raw_url)
            same_origin = _origin(raw_url) == target_origin
            reason = ""
            if parsed.scheme not in {"http", "https"}:
                reason = "unsupported-scheme"
            elif not allow_third_party and not same_origin:
                reason = "cross-origin-blocked"
            elif not allow_state_changing and request.method.upper() not in SAFE_BROWSER_METHODS:
                reason = "state-changing-method-blocked"
            else:
                try:
                    validate_target_url(raw_url)
                    if runtime is not None and request.resource_type in TRACKED_RESOURCE_TYPES:
                        runtime.before_request()
                except (RequestBudgetExceeded, ScanCancelled) as exc:
                    fatal = exc
                    reason = "scan-stopped"
                except Exception:
                    reason = "unsafe-target"
            if reason:
                inventory.blocked_requests.append({"method": request.method, "url": raw_url[:2000], "reason": reason})
                key = (request.method.upper(), raw_url)
                request_by_key[key] = BrowserRequestRecord(
                    method=request.method.upper(), url=raw_url[:2000], resource_type=request.resource_type,
                    same_origin=same_origin, blocked=True, failure=reason,
                )
                route.abort()
                return
            route.continue_()

        context.route("**/*", route_handler)
        page = context.new_page()

        def on_request(req) -> None:
            key = (req.method.upper(), req.url)
            request_by_key.setdefault(
                key,
                BrowserRequestRecord(
                    method=req.method.upper(), url=req.url[:2000], resource_type=req.resource_type,
                    same_origin=_origin(req.url) == target_origin,
                ),
            )

        def on_response(resp) -> None:
            req = resp.request
            key = (req.method.upper(), req.url)
            record = request_by_key.setdefault(
                key,
                BrowserRequestRecord(
                    method=req.method.upper(), url=req.url[:2000], resource_type=req.resource_type,
                    same_origin=_origin(req.url) == target_origin,
                ),
            )
            record.status = resp.status
            record.content_type = str(resp.headers.get("content-type", ""))[:200]

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", lambda req: setattr(request_by_key.setdefault((req.method.upper(), req.url), BrowserRequestRecord(req.method.upper(), req.url[:2000], req.resource_type)), "failure", str(req.failure or "request failed")[:500]))
        page.on("console", lambda msg: inventory.console_errors.append(msg.text[:1000]) if msg.type == "error" and len(inventory.console_errors) < 100 else None)
        page.on("pageerror", lambda exc: inventory.page_errors.append(str(exc)[:1000]) if len(inventory.page_errors) < 100 else None)
        page.on("websocket", lambda ws: inventory.websocket_urls.append(ws.url[:2000]) if ws.url not in inventory.websocket_urls and len(inventory.websocket_urls) < 100 else None)

        queue: deque[str] = deque([target])
        queued = {target}
        visited: set[str] = set()
        try:
            while queue and len(visited) < max_pages:
                if fatal:
                    raise fatal
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                try:
                    page.goto(current, wait_until="domcontentloaded")
                    page.wait_for_timeout(250)
                except PlaywrightTimeoutError:
                    inventory.warnings.append(f"Navigation timed out: {current}")
                except PlaywrightError as exc:
                    message = str(exc)
                    if "ERR_BLOCKED_BY_ADMINISTRATOR" in message:
                        inventory.warnings.append(
                            "Navigation was blocked by a local Chromium enterprise URL policy. "
                            "Use a Playwright-managed Chromium build or allow the authorized target in the browser policy."
                        )
                    else:
                        inventory.warnings.append(f"Navigation failed for {current}: {message[:300]}")
                    if fatal:
                        raise fatal
                    continue
                inventory.pages_visited.append(current)
                inventory.final_url = page.url
                if not inventory.title:
                    try:
                        inventory.title = page.title()[:300]
                    except Exception:
                        pass
                try:
                    html = page.content()
                    inventory.framework_hints = sorted(set(inventory.framework_hints + _framework_hints(html)))
                except Exception:
                    html = ""
                try:
                    links = page.eval_on_selector_all(
                        "a[href],link[href]",
                        "els => els.map(e => e.href).filter(Boolean)",
                    )
                except Exception:
                    links = []
                for raw in links[:1000]:
                    candidate = safe_url(urljoin(page.url, str(raw)))
                    if candidate and candidate not in queued:
                        queued.add(candidate)
                        inventory.discovered_links.append(candidate)
                        if len(queue) + len(visited) < max_pages * 5:
                            queue.append(candidate)
                try:
                    forms = page.eval_on_selector_all(
                        "form",
                        "forms => forms.map(f => ({action: f.action, method: (f.method || 'GET').toUpperCase(), inputs: Array.from(f.elements).map(e => ({name:e.name || '', type:e.type || '', required:!!e.required})).filter(x=>x.name).slice(0,50)}))",
                    )
                except Exception:
                    forms = []
                for form in forms[:100]:
                    if not isinstance(form, dict):
                        continue
                    action = safe_url(str(form.get("action") or page.url))
                    if action:
                        inventory.forms.append({
                            "page": page.url[:2000], "action": action,
                            "method": str(form.get("method") or "GET")[:10],
                            "inputs": form.get("inputs") or [],
                        })
        finally:
            inventory.requests = list(request_by_key.values())[:2000]
            context.close()
            browser.close()

    # Ensure no secrets are accidentally serialized from future extensions.
    clean = redact_mapping(inventory.to_dict())
    inventory.requests = [BrowserRequestRecord(**item) for item in clean.get("requests", [])]
    return inventory
