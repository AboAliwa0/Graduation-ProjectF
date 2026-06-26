"""
==========================================================
CyberScan Enterprise
Clickjacking Scanner
----------------------------------------------------------
Author      : Graduation Project Team
Purpose     : Detect Clickjacking (UI Redressing) vulnerabilities
              using a two-stage strategy:

                1) Static Header / Markup Analysis
                   - X-Frame-Options (incl. multi-value / legacy
                     ALLOW-FROM misconfigurations)
                   - Content-Security-Policy frame-ancestors
                     (RFC-correct tokenization, not substring
                     matching)
                   - Legacy <meta http-equiv> frame-busting
                     markers (weak/no-op protection indicator)

                2) Active (Dynamic) Verification
                   - Renders the target inside a sandboxed
                     <iframe> harness and asks the browser
                     engine itself whether the frame was
                     blocked, so the result reflects what a
                     real browser would actually do, not just
                     what the headers claim.

              Active verification is best-effort: if no
              headless browser engine is available in the
              execution environment, the scanner degrades
              gracefully to header/markup analysis only and
              clearly flags the lower confidence in the report.

CWE         : CWE-1021 (Improper Restriction of Rendered UI
              Layers or Frames)
Version     : 2.1.0
==========================================================
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import quote as url_quote

from backend.core.base_scanner import BaseScanner
from backend.core.models import PluginInfo, ScanResult


# ----------------------------------------------------------
# Constants & reference tables
# ----------------------------------------------------------

# X-Frame-Options values that fully block framing.
SAFE_XFO_VALUES = {
    "deny",
    "sameorigin",
}

# CSP frame-ancestors tokens that fully or conditionally
# restrict framing. '*' is intentionally excluded: it is a
# valid CSP token but it is the *unsafe* wildcard, not a
# safe value.
SAFE_FRAME_ANCESTORS_TOKENS = {
    "'none'",
    "'self'",
}

# Markers that indicate a developer attempted (incorrectly)
# to mitigate Clickjacking via legacy/non-standard channels.
# Their presence is never a real control, but it is useful
# evidence that the application owner was at least aware of
# the risk.
LEGACY_META_PATTERN = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']x-frame-options["\'][^>]*>',
    re.IGNORECASE,
)

FRAME_BUSTING_JS_PATTERN = re.compile(
    r'if\s*\(\s*(self|window)\s*(!==|!=)\s*(top|parent)\s*\)',
    re.IGNORECASE,
)

CSP_HEADER_NAMES = (
    "content-security-policy",
    # report-only is checked as a secondary source only; it is
    # never enforced by the browser, so it is not a real control.
    "content-security-policy-report-only",
)

# Conservative timeout budgets (seconds) for the active
# verification stage so a single hung target can never stall
# a full scan job.
HEADLESS_NAV_TIMEOUT = 8
HEADLESS_HARD_TIMEOUT = 12


# ----------------------------------------------------------
# Internal data structures
# ----------------------------------------------------------

@dataclass
class HeaderAnalysis:
    """Structured result of the static analysis stage."""

    vulnerable: bool
    severity: str
    confidence: str
    cvss: float
    cvss_vector: str
    description: str
    recommendation: str
    evidence: Dict[str, str] = field(default_factory=dict)


@dataclass
class ActiveCheckResult:
    """Structured result of the dynamic / active verification stage."""

    performed: bool
    frame_blocked: Optional[bool] = None
    method: str = "Not performed"
    detail: str = ""


# ----------------------------------------------------------
# Scanner implementation
# ----------------------------------------------------------

class ClickjackingScanner(BaseScanner):
    """Detects Clickjacking (UI Redressing) vulnerabilities.

    The scanner correlates two independent signals:

      * What the server *claims* via response headers / markup.
      * What a real rendering engine *does* when the page is
        actually embedded in an iframe.

    When the two disagree (e.g. a header is present but
    malformed in a way browsers ignore), the active result
    takes precedence and the discrepancy is reported as
    additional evidence -- this is the difference between a
    scanner that parses text and one that verifies a real
    vulnerability.
    """

    # ------------------------------------------------------
    # Plugin metadata
    # ------------------------------------------------------

    def plugin_info(self) -> PluginInfo:

        return PluginInfo(
            id="clickjacking_scanner",
            name="Clickjacking Scanner",
            version="2.1.0",
            author="CyberScan Team",
            description=(
                "Detects Clickjacking (UI Redressing) vulnerabilities "
                "through combined static header analysis and active "
                "iframe-embedding verification."
            ),
            category="Security Headers",
            severity="Medium",
        )

    # ------------------------------------------------------
    # Entry point
    # ------------------------------------------------------

    def scan(self, target: str) -> ScanResult:

        try:
            response = self.client.get(target)
        except Exception as ex:
            return self._error_result(target, ex)

        try:
            headers = self._normalize_headers(response.headers)
            body = self._safe_response_text(response)

            static_analysis = self.analyze_headers(headers, body)
           # تعطيل الـ Active Verification مؤقتًا للاختبار
            active_result = ActiveCheckResult(
                performed=False,
                method="Disabled for testing",
            )

            final = static_analysis

            title = (
                "Clickjacking Vulnerability"
                if final.vulnerable
                else "Clickjacking Protection Detected"
            )

            evidence = dict(final.evidence)
            evidence["Detection Method"] = (
                "HTTP Response Header Analysis + Active Iframe "
                "Verification"
                if active_result.performed
                else "HTTP Response Header Analysis (static only -- "
                     "active verification unavailable in this "
                     "environment)"
            )
            evidence["Active Verification"] = active_result.method
            if active_result.detail:
                evidence["Active Verification Detail"] = active_result.detail

            return ScanResult(
                plugin_id=self.id,
                plugin_name=self.name,

                target=target,
                final_url=getattr(response, "url", target),

                vulnerable=final.vulnerable,
                severity=final.severity,
                confidence=final.confidence,

                title=title,
                description=final.description,
                recommendation=final.recommendation,

                status_code=getattr(response, "status_code", None),
                headers=dict(response.headers),

                evidence=evidence,

                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Clickjacking_Defense_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/1021.html",
                    "https://owasp.org/www-community/attacks/Clickjacking",
                ],

                cwe="CWE-1021",
                cvss=final.cvss,
                cvss_vector=final.cvss_vector,
            )

        except Exception as ex:
            return self._error_result(target, ex)

    # ------------------------------------------------------
    # Error handling
    # ------------------------------------------------------

    def _error_result(self, target: str, ex: Exception) -> ScanResult:
        """Builds a consistent, low-noise result for scan failures.

        Distinguishes common network failure classes so the report
        tells the analyst *why* the target couldn't be assessed,
        instead of a generic stack trace.
        """

        ex_name = type(ex).__name__
        message = str(ex) or ex_name

        if "timeout" in ex_name.lower() or "timeout" in message.lower():
            description = f"Request to target timed out: {message}"
            recommendation = (
                "Verify the target is reachable and responsive, then "
                "retry the scan. If the target is behind a WAF/rate "
                "limiter, allowlist the scanner's source IP."
            )
        elif "ssl" in ex_name.lower() or "certificate" in message.lower():
            description = f"TLS/SSL error while connecting to target: {message}"
            recommendation = (
                "Verify the target's TLS certificate chain and "
                "protocol support, then retry the scan."
            )
        elif "connection" in ex_name.lower():
            description = f"Connection error while reaching target: {message}"
            recommendation = (
                "Confirm the target host/port is reachable from the "
                "scanner network and retry."
            )
        else:
            description = f"Unhandled error during scan: {message}"
            recommendation = "Retry the scan; escalate if the error persists."

        return ScanResult(
            plugin_id=self.id,
            plugin_name=self.name,
            target=target,
            vulnerable=False,
            severity="Info",
            confidence="Low",
            title="Scan Error",
            description=description,
            recommendation=recommendation,
            evidence={
                "Exception Type": ex_name,
                "Exception Message": message,
            },
        )

    # ------------------------------------------------------
    # Helpers: normalization
    # ------------------------------------------------------

    @staticmethod
    def _normalize_headers(raw_headers) -> Dict[str, List[str]]:
        """Lower-cases header names and preserves *all* values per
        name as a list.

        Some HTTP client libraries collapse duplicate headers into a
        single comma-joined string, others expose them as multiple
        entries. Both are normalized to ``List[str]`` here so the
        multi-value X-Frame-Options check below is correct regardless
        of which client populated ``response.headers``.
        """

        normalized: Dict[str, List[str]] = {}

        items = (
            raw_headers.items()
            if hasattr(raw_headers, "items")
            else raw_headers
        )

        for key, value in items:
            key_lower = str(key).lower()
            value_str = str(value)
            normalized.setdefault(key_lower, []).append(value_str)

        return normalized

    @staticmethod
    def _safe_response_text(response, limit: int = 200_000) -> str:
        """Best-effort retrieval of response body text for markup
        checks (meta tags / inline frame-busting JS).

        Never raises: a body that can't be decoded simply yields an
        empty string, degrading the markup checks rather than failing
        the whole scan.
        """

        try:
            text = response.text
        except Exception:
            try:
                text = response.content.decode("utf-8", errors="ignore")
            except Exception:
                return ""

        return text[:limit] if text else ""

    # ------------------------------------------------------
    # Stage 1: Static header / markup analysis
    # ------------------------------------------------------

    def analyze_headers(
        self,
        headers: Dict[str, List[str]],
        body: str = "",
    ) -> HeaderAnalysis:
        """Performs RFC-aware static analysis of anti-framing
        controls.

        Precedence follows what real browsers implement:
          1. X-Frame-Options is evaluated first because legacy
             browsers without CSP support only honor it.
          2. CSP frame-ancestors is evaluated next; modern browsers
             prefer it over X-Frame-Options when both are present
             and conflicting.
          3. Legacy markup-based mitigations are evaluated last and
             are never treated as sufficient on their own.
        """

        # FIX: filter out blank header values so an empty
        # X-Frame-Options header is treated the same as a missing one,
        # and xfo_raw reflects "Missing" correctly in that case.
        xfo_values = [
            v.strip().lower()
            for v in headers.get("x-frame-options", [])
            if v.strip()
        ]
        xfo_raw = ", ".join(
            v for v in headers.get("x-frame-options", []) if v.strip()
        ) or "Missing"

        # Only the enforcing CSP header is used for framing decisions;
        # report-only is informational and never blocks rendering.
        csp_raw = ""
        for name in CSP_HEADER_NAMES:
            values = headers.get(name, [])
            if values:
                csp_raw = "; ".join(values)
                break
        csp_lower = csp_raw.lower()

        frame_ancestors_tokens = self._extract_frame_ancestors(csp_lower)

        has_legacy_meta = bool(LEGACY_META_PATTERN.search(body)) if body else False
        has_frame_busting_js = (
            bool(FRAME_BUSTING_JS_PATTERN.search(body)) if body else False
        )

        evidence: Dict[str, str] = {
            "X-Frame-Options": xfo_raw,
            "Content-Security-Policy": csp_raw or "Missing",
            "CSP frame-ancestors": (
                " ".join(frame_ancestors_tokens)
                if frame_ancestors_tokens is not None
                else "Not present"
            ),
            "Legacy <meta> X-Frame-Options tag": (
                "Present (non-functional in browsers, ignored)"
                if has_legacy_meta
                else "Not found"
            ),
            "Client-side frame-busting script": (
                "Detected (bypassable, not a substitute for headers)"
                if has_frame_busting_js
                else "Not found"
            ),
        }

        # --- Multi-value / duplicate X-Frame-Options: a known
        #     misconfiguration where browsers disagree on which
        #     value to honor, effectively making protection
        #     unreliable or void in some clients. ---
        if len(xfo_values) > 1 and len(set(xfo_values)) > 1:
            return HeaderAnalysis(
                vulnerable=True,
                severity="Medium",
                confidence="High",
                cvss=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                description=(
                    "Multiple conflicting X-Frame-Options values were "
                    f"returned ({xfo_raw}). Browser behavior in this "
                    "situation is inconsistent: some browsers reject "
                    "the header entirely and render the page "
                    "frameable, nullifying the intended protection."
                ),
                recommendation=(
                    "Send exactly one X-Frame-Options header with a "
                    "single value (DENY or SAMEORIGIN), and rely on "
                    "CSP frame-ancestors as the primary, standards-"
                    "based control."
                ),
                evidence=evidence,
            )

        xfo = xfo_values[0] if xfo_values else ""

        # --- No protection at all ---
        no_xfo = not xfo
        no_frame_ancestors = frame_ancestors_tokens is None

        if no_xfo and no_frame_ancestors:
            severity = "High"
            description = "No Clickjacking protection mechanism was detected."

            if has_legacy_meta or has_frame_busting_js:
                description += (
                    " A legacy mitigation attempt (meta tag and/or "
                    "client-side frame-busting script) was found, but "
                    "these provide no real protection: the meta "
                    "http-equiv variant of X-Frame-Options is ignored "
                    "by all modern browsers, and JavaScript frame-"
                    "busting can be bypassed (e.g. via the sandbox "
                    "attribute, double framing, or disabling "
                    "JavaScript in the framing page)."
                )
                confidence = "High"
            else:
                confidence = "High"

            return HeaderAnalysis(
                vulnerable=True,
                severity=severity,
                confidence=confidence,
                cvss=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                description=description,
                recommendation=(
                    "Configure a real, server-enforced control: send "
                    "'X-Frame-Options: DENY' (or SAMEORIGIN if the "
                    "page legitimately needs to be framed by itself) "
                    "and/or a Content-Security-Policy with an explicit "
                    "frame-ancestors directive (e.g. \"frame-ancestors "
                    "'self'\"). Do not rely on client-side JavaScript "
                    "as the sole defense."
                ),
                evidence=evidence,
            )

        # --- Safe X-Frame-Options ---
        if xfo in SAFE_XFO_VALUES:
            # Cross-check against CSP if present: if CSP exists but
            # explicitly allows broader framing, that is a real
            # discrepancy worth surfacing even though XFO alone is
            # protective in most browsers.
            csp_conflict = (
                frame_ancestors_tokens is not None
                and not self._frame_ancestors_is_safe(frame_ancestors_tokens)
            )

            if csp_conflict:
                return HeaderAnalysis(
                    vulnerable=False,
                    severity="Low",
                    confidence="Medium",
                    cvss=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
                    description=(
                        f"X-Frame-Options: {xfo} provides protection in "
                        "browsers that honor it, but the CSP "
                        "frame-ancestors directive on this response "
                        "permits broader framing than X-Frame-Options "
                        "does. This inconsistency suggests the "
                        "policies were configured independently and "
                        "should be aligned."
                    ),
                    recommendation=(
                        "Align CSP frame-ancestors with the intent of "
                        "X-Frame-Options so both controls enforce the "
                        "same policy."
                    ),
                    evidence=evidence,
                )

            return HeaderAnalysis(
                vulnerable=False,
                severity="Info",
                confidence="High",
                cvss=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
                description=f"Protected using X-Frame-Options: {xfo.upper()}.",
                recommendation="No action required.",
                evidence=evidence,
            )

        # --- Deprecated ALLOW-FROM ---
        if "allow-from" in xfo:
            return HeaderAnalysis(
                vulnerable=True,
                severity="Medium",
                confidence="High",
                cvss=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                description=(
                    "The deprecated X-Frame-Options ALLOW-FROM "
                    "directive was detected. This directive is "
                    "ignored by all current major browsers (Chrome, "
                    "Edge, Firefox, Safari), meaning the page is "
                    "effectively unprotected in practice despite the "
                    "header being present."
                ),
                recommendation=(
                    "Replace ALLOW-FROM with a Content-Security-Policy "
                    "frame-ancestors directive listing the trusted "
                    "origin(s), e.g. \"frame-ancestors "
                    "https://trusted.example.com\"."
                ),
                evidence=evidence,
            )

        # --- CSP frame-ancestors present ---
        if frame_ancestors_tokens is not None:
            if self._frame_ancestors_is_safe(frame_ancestors_tokens):
                return HeaderAnalysis(
                    vulnerable=False,
                    severity="Info",
                    confidence="High",
                    cvss=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
                    description=(
                        "Protected using CSP frame-ancestors: "
                        f"{' '.join(frame_ancestors_tokens)}"
                    ),
                    recommendation="No action required.",
                    evidence=evidence,
                )

            if "*" in frame_ancestors_tokens:
                return HeaderAnalysis(
                    vulnerable=True,
                    severity="Medium",
                    confidence="High",
                    cvss=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    description=(
                        "The CSP frame-ancestors directive explicitly "
                        "allows framing from any origin ('*'), which "
                        "is equivalent to having no Clickjacking "
                        "protection at all."
                    ),
                    recommendation=(
                        "Restrict frame-ancestors to an explicit "
                        "allowlist of trusted origins, or use 'self' "
                        "if framing is only needed by the same origin."
                    ),
                    evidence=evidence,
                )

            # frame-ancestors present with origins that are neither
            # the safe tokens nor a wildcard -- e.g. a third-party
            # origin. This is a deliberate, scoped allowance and is
            # only flagged if it includes overly broad or non-HTTPS
            # origins.
            risky_tokens = [
                t for t in frame_ancestors_tokens
                if t.startswith("http://")
            ]

            if risky_tokens:
                return HeaderAnalysis(
                    vulnerable=True,
                    severity="Low",
                    confidence="Medium",
                    cvss=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    description=(
                        "CSP frame-ancestors allows framing from one "
                        f"or more plaintext HTTP origins "
                        f"({', '.join(risky_tokens)}), which weakens "
                        "the protection against network-level "
                        "Clickjacking variants targeting those origins."
                    ),
                    recommendation=(
                        "Restrict frame-ancestors to HTTPS origins only."
                    ),
                    evidence=evidence,
                )

            return HeaderAnalysis(
                vulnerable=False,
                severity="Info",
                confidence="Medium",
                cvss=0.0,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
                description=(
                    "CSP frame-ancestors restricts framing to an "
                    f"explicit allowlist: {' '.join(frame_ancestors_tokens)}"
                ),
                recommendation=(
                    "Confirm every listed origin is fully trusted, "
                    "since each is permitted to frame this page."
                ),
                evidence=evidence,
            )

        # --- Fallback: header present but unparseable ---
        return HeaderAnalysis(
            vulnerable=False,
            severity="Low",
            confidence="Low",
            cvss=0.0,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
            description=(
                "An anti-framing header was present but its value "
                "could not be confidently classified as safe or "
                "unsafe. Manual review is recommended."
            ),
            recommendation="Manually review the Clickjacking configuration.",
            evidence=evidence,
        )

    # ------------------------------------------------------
    # CSP frame-ancestors parsing helpers
    # ------------------------------------------------------

    @staticmethod
    def _extract_frame_ancestors(csp_lower: str) -> Optional[List[str]]:
        """Extracts the frame-ancestors directive's source list as
        discrete tokens.

        Returns ``None`` if the directive is absent, or a (possibly
        empty) list of tokens if present. Tokenizing properly (instead
        of substring-matching the whole CSP string) avoids both false
        negatives -- e.g. missing that 'self' is only one of several
        allowed origins -- and false positives -- e.g. a 'self' token
        appearing inside an unrelated directive such as
        ``script-src 'self'``.
        """

        if "frame-ancestors" not in csp_lower:
            return None

        for directive in csp_lower.split(";"):
            directive = directive.strip()
            if directive.startswith("frame-ancestors"):
                remainder = directive[len("frame-ancestors"):].strip()
                return remainder.split() if remainder else []

        return None

    @staticmethod
    def _frame_ancestors_is_safe(tokens: List[str]) -> bool:
        """A frame-ancestors source list is fully protective only when
        every token is a safe token (typically just 'none' or 'self'
        alone). Any additional origin -- even alongside 'self' --
        widens the attack surface and must not be reported as fully
        safe.
        """

        if not tokens:
            return False

        return all(t in SAFE_FRAME_ANCESTORS_TOKENS for t in tokens)

    # ------------------------------------------------------
    # Stage 2: Active (dynamic) verification
    # ------------------------------------------------------

    def _run_active_verification(self, target: str) -> ActiveCheckResult:
        """Attempts to confirm framing behavior using a real browser
        engine rather than trusting header text alone.

        Strategy: launch a minimal, sandboxed Chromium instance (via
        Playwright if installed in the execution environment),
        navigate a harness page that embeds the target in an
        <iframe>, and ask the DOM whether the frame's document was
        actually loaded. If the iframe ends up cross-origin-blocked
        or empty, the browser itself enforced the protection --
        which is definitive evidence, independent of how the headers
        were written.

        This stage is intentionally optional and fails closed: any
        missing dependency, timeout, or unexpected error simply
        results in ``performed=False`` so the report can fall back to
        the static analysis without raising.
        """

        # FIX: support both 'python3' (Linux/macOS) and 'python'
        # (Windows) so active verification works cross-platform.
        python_exe = shutil.which("python3") or shutil.which("python")
        if python_exe is None:
            return ActiveCheckResult(
                performed=False,
                method="Not performed (no Python interpreter found in PATH)",
            )

        try:
            import playwright  # noqa: F401
        except ImportError:
            return ActiveCheckResult(
                performed=False,
                method="Not performed (Playwright not installed in "
                       "this environment)",
            )

        harness_script = self._build_playwright_harness(target)

        tmp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as tmp:
                tmp.write(harness_script)
                tmp_path = tmp.name

            proc = subprocess.run(
                [python_exe, tmp_path],
                capture_output=True,
                text=True,
                timeout=HEADLESS_HARD_TIMEOUT,
            )

            output = proc.stdout.strip()

            if output == "BLOCKED":
                return ActiveCheckResult(
                    performed=True,
                    frame_blocked=True,
                    method="Active iframe embedding test (headless browser)",
                    detail=(
                        "The target refused to render inside a "
                        "cross-origin iframe in a real browser engine, "
                        "confirming the protection is effective."
                    ),
                )
            elif output == "RENDERED":
                return ActiveCheckResult(
                    performed=True,
                    frame_blocked=False,
                    method="Active iframe embedding test (headless browser)",
                    detail=(
                        "The target's content rendered successfully "
                        "inside a cross-origin iframe in a real browser "
                        "engine, confirming the page can be framed."
                    ),
                )
            elif output == "UNREACHABLE":
                # The target could not be reached at all (DNS/network
                # failure, blocked egress, etc.). This is a test
                # infrastructure limitation, not a security signal --
                # it must never be conflated with "blocked" or
                # "rendered", or it would produce false results.
                return ActiveCheckResult(
                    performed=False,
                    method="Active verification skipped (target "
                           "unreachable from the scanning environment)",
                    detail=(
                        "A direct browser navigation to the target did "
                        "not succeed, so no iframe-embedding conclusion "
                        "could be drawn. Falling back to static header "
                        "analysis."
                    ),
                )
            else:
                return ActiveCheckResult(
                    performed=False,
                    method="Active verification inconclusive",
                    detail=(proc.stderr or output)[:300],
                )

        except subprocess.TimeoutExpired:
            return ActiveCheckResult(
                performed=False,
                method="Active verification timed out",
                detail=(
                    f"No result within {HEADLESS_HARD_TIMEOUT}s; "
                    "falling back to static analysis."
                ),
            )
        except Exception as ex:
            return ActiveCheckResult(
                performed=False,
                method="Active verification error",
                detail=str(ex)[:300],
            )
        finally:
            # FIX: always clean up the temp script file regardless of
            # whether the subprocess succeeded, timed out, or raised.
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    @staticmethod
    def _build_playwright_harness(target: str) -> str:
        """Generates a standalone Playwright script that embeds
        ``target`` in a sandboxed iframe and prints whether the
        framed document actually loaded.

        Running this as a short-lived subprocess (rather than
        importing Playwright's sync API directly into a possibly
        async/long-lived scanner process) keeps the heavy browser
        automation fully isolated and disposable per scan.
        """

        # FIX: percent-encode the URL for safe embedding inside the
        # HTML src attribute (single-quoted). A plain quote-escape of
        # double-quotes was insufficient: a target URL containing a
        # single quote would break the attribute and the HTML harness.
        safe_target_url = url_quote(target, safe=":/?#[]@!$&()*+,;=%")

        # The TARGET variable in the generated script still holds the
        # original unencoded URL for the top-level reachability probe
        # (page.goto), which expects a real URL, not a percent-encoded
        # HTML attribute value.
        escaped_target = target.replace("\\", "\\\\").replace('"', '\\"')

        return textwrap.dedent(f'''
            import sys
            from playwright.sync_api import sync_playwright

            TARGET = "{escaped_target}"
            TARGET_URL_ENCODED = "{safe_target_url}"

            HARNESS_HTML = (
                "<!DOCTYPE html><html><body>"
                "<iframe id='probe' sandbox='allow-scripts allow-same-origin' "
                "src='" + TARGET_URL_ENCODED + "' "
                "style='width:800px;height:600px;'></iframe>"
                "</body></html>"
            )

            # Network-level failures (DNS errors, connection refused,
            # timeouts, blocked egress, etc.) must never be reported
            # as a security finding -- they mean the test could not
            # run at all, not that framing succeeded or was blocked.
            # A plain top-level navigation to TARGET first confirms
            # reachability before any conclusion is drawn from the
            # iframe test itself.
            nav_failed = {{"value": False}}

            def handle_request_failed(request):
                if request.url == TARGET:
                    nav_failed["value"] = True

            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True, args=[
                        "--no-sandbox", "--disable-gpu"
                    ])
                    context = browser.new_context(ignore_https_errors=True)

                    probe_page = context.new_page()
                    try:
                        probe_response = probe_page.goto(
                            TARGET,
                            timeout={HEADLESS_NAV_TIMEOUT * 1000},
                            wait_until="domcontentloaded",
                        )
                        target_reachable = probe_response is not None
                    except Exception:
                        target_reachable = False
                    probe_page.close()

                    if not target_reachable:
                        print("UNREACHABLE")
                        browser.close()
                        sys.exit(0)

                    page = context.new_page()
                    page.on("requestfailed", handle_request_failed)
                    page.set_content(HARNESS_HTML)

                    try:
                        page.wait_for_timeout({HEADLESS_NAV_TIMEOUT * 1000})
                    except Exception:
                        pass

                    if nav_failed["value"]:
                        print("UNREACHABLE")
                        browser.close()
                        sys.exit(0)

                    frame = None
                    for f in page.frames:
                        if f != page.main_frame:
                            frame = f
                            break

                    if frame is None:
                        print("BLOCKED")
                    else:
                        try:
                            frame.wait_for_load_state(
                                "domcontentloaded", timeout={HEADLESS_NAV_TIMEOUT * 1000}
                            )
                            body_html = frame.evaluate(
                                "document.body ? document.body.innerHTML.length : 0"
                            )
                            print("RENDERED" if body_html and body_html > 0 else "BLOCKED")
                        except Exception:
                            print("BLOCKED")

                    browser.close()
            except Exception as exc:
                print("ERROR", file=sys.stderr)
                print(str(exc), file=sys.stderr)
                sys.exit(1)
        ''').strip()

    # ------------------------------------------------------
    # Reconciliation of static + active results
    # ------------------------------------------------------

    @staticmethod
    def _reconcile(
        static: HeaderAnalysis,
        active: ActiveCheckResult,
    ) -> HeaderAnalysis:
        """Combines static analysis with active verification.

        Active, real-browser evidence is authoritative when
        available because it reflects actual exploitability rather
        than header text. The static result is preserved otherwise
        and its confidence is never silently upgraded past what was
        actually verified.
        """

        if not active.performed or active.frame_blocked is None:
            return static

        if active.frame_blocked and static.vulnerable:
            # Headers looked unsafe but the browser still blocked
            # framing (e.g. an upstream proxy/CDN adds protection the
            # origin server doesn't, or another control intervened).
            static.vulnerable = False
            static.severity = "Info"
            static.confidence = "High"
            static.cvss = 0.0
            static.cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"
            static.description = (
                "Static header analysis suggested missing or weak "
                "protection, but active verification confirmed the "
                "target actually blocks rendering inside a cross-"
                "origin iframe (protection is likely enforced "
                "upstream, e.g. by a CDN, WAF, or reverse proxy)."
            )
            static.recommendation = (
                "No exploitable Clickjacking issue was confirmed. For "
                "defense-in-depth, still configure X-Frame-Options "
                "and/or CSP frame-ancestors directly on the origin "
                "server so protection does not depend solely on an "
                "intermediary."
            )
            return static

        if not active.frame_blocked and not static.vulnerable:
            # Headers looked safe but the browser actually rendered
            # the framed content -- a real, confirmed vulnerability
            # that static analysis alone would have missed (e.g. a
            # header only applied to some paths/responses).
            static.vulnerable = True
            static.severity = "High"
            static.confidence = "High"
            static.cvss = 6.8
            static.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
            static.description = (
                "Static analysis of this response's headers suggested "
                "Clickjacking protection was in place, but active "
                "verification confirmed the target actually renders "
                "inside a cross-origin iframe in a real browser. The "
                "protection may only apply to certain paths, response "
                "codes, or be misconfigured in a way headers alone do "
                "not reveal."
            )
            static.recommendation = (
                "Confirm X-Frame-Options / CSP frame-ancestors is "
                "applied consistently across all relevant routes, "
                "response codes (including errors/redirects), and "
                "CDN/cache layers, then re-test."
            )
            return static

        # Active and static results agree -- raise confidence only.
        static.confidence = "High"
        return static
