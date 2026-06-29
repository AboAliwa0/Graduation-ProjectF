# CyberScan Project Context for AI Assistants

## 1. Project Overview

- **Project:** CyberScan Professional 5.0
- **Purpose:** An authorized, low-impact Dynamic Application Security Testing (DAST) platform for web applications and APIs. It runs selected scanner modules, records evidence and confidence, stores results, and exports reports.
- **Stack:** Python, Flask, Flask-SocketIO, Flask-Bcrypt, Flask-JWT-Extended, SQLite, Requests, BeautifulSoup, ReportLab, Playwright, optional Redis workers, WebSocket and gRPC libraries.
- **Local run:** On Windows run `setup_and_run.bat`; manually, create/activate `.venv`, install `requirements.txt`, run `playwright install chromium`, configure `.env`, then run `python app.py`. Default URL is `http://127.0.0.1:5000`.
- **Main entry point:** `app.py`. `wsgi.py` exposes the Flask app for Gunicorn; `worker.py` runs Redis-backed scan jobs.

## 2. Folder Structure

```text
Graduation-ProjectF/
|-- app.py                    # Flask app, routes, orchestration, exports
|-- database.py               # SQLite schema, migrations, audit logging
|-- main.py                   # Dynamic scanner loader
|-- routes_ai.py              # Authenticated AI-analysis endpoint
|-- ai_analyzer.py            # AI prompt and provider integration
|-- worker.py / wsgi.py       # Distributed worker / production entry
|-- services/
|   |-- scan_runtime.py       # Request budget and cancellation context
|   |-- scan_manager.py       # Bounded local executor
|   |-- distributed_queue.py  # Encrypted Redis queue
|   |-- browser_crawler.py    # Playwright SPA crawler
|   `-- ...                   # API, auth, OAST, GraphQL, WS, gRPC helpers
|-- vulnerabilities/          # 26 scanner modules plus common.py
|-- templates/                # Dashboard, history, details, auth pages
|-- static/js/dashboard-pro.js
|-- static/css/               # Existing UI styles
|-- tests/                    # App, runtime, database and scanner tests
|-- docs/                     # Architecture, API and scanner matrix
|-- README.md / DEMO_GUIDE.md
`-- .env.example / requirements.txt
```

## 3. Core Files

- `app.py`: authentication, CSRF, Session/JWT access, scanner catalog, target scopes, dashboard APIs, scan orchestration, status/cancel routes, result normalization, risk scoring, PDF/JSON/SARIF/artifact/HAR exports, Socket.IO events.
- `database.py`: creates `users`, `scans`, `audit_logs`, and `target_scopes`; enables foreign keys and WAL; performs additive migration for older databases.
- `main.py`: discovers every importable `vulnerabilities.*` module exposing `scan()`; excludes `common.py`.
- `services/scan_runtime.py`: per-scan Requests session, request counter/budget, cancellation and ephemeral credentials/artifacts.
- `services/scan_manager.py`: bounded in-process execution. Jobs do not survive restart; database initialization marks active local jobs `interrupted`.
- `services/distributed_queue.py` and `worker.py`: optional encrypted Redis job transport and recovery.
- `vulnerabilities/common.py`: standardized result envelope, safe URL validation, SSRF/private-IP controls, redirect handling, response-size limits, query replacement, text/fingerprint helpers.
- `templates/dashboard.html` + `static/js/dashboard-pro.js`: real dashboard and New Scan modal. They fetch the scanner catalog, render dynamic inputs, submit `/scan-live`, poll status, and display statistics/findings.
- `templates/history.html`: server-rendered user-owned scan history.
- `templates/scan_details.html`: normalized findings, evidence, OWASP/ASVS, CVSS, progress, artifacts, and export links.
- `routes_ai.py` / `ai_analyzer.py`: authenticated and CSRF-protected AI analysis. Availability depends on provider configuration.

## 4. Scan Workflow

1. An authenticated user opens the New Scan modal. JavaScript loads `/api/scanners`, selects a mode/preset, and displays each selected module's inputs.
2. The browser sends `POST /scan-live` with `url`, `vulns`, `authorized: true`, mode, request budget, TLS choice, `scanner_inputs`, and optional ephemeral auth context.
3. The server validates authentication, CSRF, authorization confirmation, URL/DNS, host allowlist, user scope, TLS policy, scanner IDs, budget, and concurrency.
4. A `scans` row is created with status `queued`. Secrets such as cookies and auth profiles are removed from persisted job metadata.
5. Local mode submits `run_scan()` to a bounded executor. Redis mode encrypts and queues the job for `worker.py`.
6. `run_scan()` activates `ScanRuntime`, executes selected modules sequentially, catches module failures, updates partial results/progress/request count, and emits scoped Socket.IO logs.
7. Final status is `done`, `cancelled`, `budget_exhausted`, or `failed`. Results, sanitized artifacts and risk score are saved to SQLite.
8. Dashboard uses `/api/history`, `/api/dashboard-stats`, and `/scan-status/<id>`. History and `/scan/<id>` show owned scans. Export routes reuse the same ownership check.

## 5. Active Vulnerability Modules

All modules return a common dictionary containing `vulnerable`, `status`, `severity`, `confidence`, `result`, `evidence`, `recommendation`, `endpoint`, `parameter`, `cwe`, `cvss`, and `requests_made`. `TEST_RESULTS.json` records 54/54 tests passing on 2026-06-26; this is test-suite coverage, not universal vulnerability coverage.

| File / module | Inputs | Check and result behavior | State |
|---|---|---|---|
| `auth_scanner.py` | login URL/fields/test user/marker | Five failed logins; reports missing throttling as potential | Tested |
| `authorization_matrix_scanner.py` | endpoints, limit | Compares read-only responses across auth profiles | Tested; profile-dependent |
| `blind_xss.py` | param, callback URL | Confirms only an observed OAST script callback | Tested; public callback-dependent |
| `clickjacking_scanner.py` | none | X-Frame-Options and CSP `frame-ancestors` | Tested |
| `cors_scanner.py` | none | Origin reflection, null origin, credentials, preflight | Tested |
| `csrf_scan.py` | none | Finds state-changing forms without visible CSRF controls | Tested heuristic/potential |
| `dir_scan.py` | optional paths | Small directory-listing probe set | Tested |
| `file_upload.py` | upload URL/field/public URL | Uploads and retrieves a harmless HTML marker | Tested; target-specific |
| `graphql_scanner.py` | endpoint | Safe introspection and schema inventory | Tested; inventory/potential |
| `grpc_scanner.py` | host:port, TLS | gRPC reflection inventory only | Tested; service-dependent |
| `host_header_scanner.py` | none | External redirect or body use of injected host | Tested |
| `html_injection.py` | param | Parses a reflected harmless custom element | Tested |
| `idor.py` | param, two IDs, marker/auth | Compares authorized and denied objects | Tested; requires known IDs |
| `info_scan.py` | none | Stack traces, secret patterns, debug pages, headers | Tested |
| `modern_spa_scanner.py` | page limit/timeout/state changes | Chromium route, form, XHR/fetch and WS inventory | Tested; Playwright-dependent |
| `oidc_scanner.py` | discovery path | OIDC transport, algorithms, PKCE and flow metadata | Tested; inventory/potential |
| `open_redirect_scanner.py` | param | Confirms an external 3xx without following it | Tested |
| `openapi_scanner.py` | document URL, probe limit | OpenAPI inventory and safe GET/HEAD/OPTIONS probes | Tested; contract-dependent |
| `path_traversal.py` | param, canary/marker | Canary or operating-system signature checks | Tested; canary preferred |
| `rate_limit.py` | none | Five requests and explicit throttling observation | Tested heuristic/potential |
| `sql_injection.py` | param | Error and repeated boolean-differential checks | Tested |
| `ssrf_scanner.py` | param, callback URL | Confirms only a unique OAST callback | Tested; callback-dependent |
| `stored_xss_scanner.py` | submit/view URLs, field | Stores then finds an executable harmless marker | Tested; state-changing/configured |
| `weak_password_scanner.py` | login fields/test credential/markers | Verifies one supplied test credential; no brute force | Tested; credential-dependent |
| `websocket_scanner.py` | endpoint, origin | Safe handshake and metadata; no application fuzzing | Tested; inventory/potential |
| `xss.py` | optional param | Reflected XSS across parsed executable contexts | Tested |

## 6. Reflected XSS Module Details

- **Path:** `vulnerabilities/xss.py`.
- **Parameter selection:** manual UI value first, then existing URL query names, then discovered GET-form fields, then `search`, `q`, `query`, `s`, and `keyword` fallbacks.
- **Query handling:** existing values are replaced, not duplicated:

```python
query = [(k, v) for k, v in query if k != name]
query.append((name, value))
```

- **Payloads:** one unique `xss-...` token is embedded in script tags, event-handler breakouts, textarea/title breakouts, JavaScript-string breakouts and `javascript:` URLs.
- **Requests:** `safe_request("GET", ...)` enforces target validation, redirect limits, TLS policy, response-size limits, cancellation, and request budget.
- **Confirmation:** BeautifulSoup searches for the exact marker in a non-inert `<script>`, an event-handler attribute, or a JavaScript URL. A baseline token request must not already appear executable.
- **Confirmed result:** High severity, High confidence, CWE-79, CVSS 8.2, evidence containing target source, baseline, payload, context and attempts.
- **Weaknesses:** GET only; static parsing does not execute JavaScript; it can miss DOM XSS, POST forms, browser transformations, and framework-specific sinks. Common-parameter fallback may consume 45 requests (five targets times baseline plus eight payloads). Query duplication was a historical issue but is fixed in the current helper.

## 7. Risk Score Logic

`app.py` adds only `confirmed` and `potential` findings. Severity weight is multiplied by confidence and by `1.0` for confirmed or `0.45` for potential, then capped at 100.

```python
weights = {"Critical": 40.0, "High": 25.0, "Medium": 12.0, "Low": 5.0, "Info": 1.0}
status_factor = 1.0 if item.get("status") == "confirmed" else 0.45
score += weights[severity] * confidence_factor * status_factor
```

A single confirmed High finding with High confidence therefore contributes exactly `25/100`. This is an additive portfolio risk score, not CVSS and not a percentage translation of the word "High". The dashboard ring, Scan Details, and PDF display the stored `scans.risk_score`; security score is `100 - risk_score`.

## 8. UI Pages

- **Dashboard (`/dashboard`):** real operational workflow with statistics, selected-scan summary, risk ring, findings, modules, scopes, audit events, and live progress.
- **New Scan:** a real modal inside Dashboard, not a separate route. Dynamic scanner input panels are generated from `/api/scanners`.
- **History (`/history`):** real server-rendered list of the current user's scans.
- **Scan Details (`/scan/<id>`):** real owner-only normalized result view with export links.
- **Report:** no HTML report page. `/scan/<id>/report` dynamically builds a ReportLab PDF.
- **Scanner Studio/modules:** no Scanner Studio route exists. "Scanner Modules" is a real Dashboard section/catalog, not an editor. No explicit "coming soon" or placeholder module was found.

## 9. Current Problems / Improvement Opportunities

1. `is_finding()` treats `status == "error"` as a finding. Scanner failures can inflate finding totals and appear beside vulnerabilities, while risk scoring ignores them.
2. A High finding showing `25/100` is mathematically correct but easy to misunderstand because the UI does not explain that risk is additive and confidence/status weighted.
3. Reflected XSS does not execute a browser and supports only GET parameter flows; POST and DOM-based XSS can be missed.
4. XSS fallback can spend a large part of the default request budget before later modules run.
5. Several scanners require explicit target knowledge, credentials, IDs, callbacks, browser binaries, contracts, or protocol services. Missing setup yields inconclusive/error, not proof of safety.
6. ReportLab uses a simple Letter-page table and default fonts; long evidence, wide URLs, Arabic text, and page splitting may format poorly.
7. `app.py` combines web, auth, orchestration, normalization and export responsibilities, increasing change risk.
8. Local jobs cannot survive restart; SQLite/WAL and in-memory auth rate limits are suitable for a demo or small deployment, not multi-node scale.
9. Unknown scanner names default to OWASP A05/ASVS Configuration, which may misclassify future modules.
10. No explicit placeholder scanner was found. Treat inventory/potential modules as intentionally conservative, not confirmed exploit scanners.

## 10. Recommended Safe Next Changes

### Must fix before demo

1. Separate scanner execution errors from security findings in counts/details/PDF while retaining them in an operational-errors section.
2. Add a one-line tooltip/label explaining risk score and its difference from CVSS/severity.
3. Use an authorized local test lab and supply exact scanner inputs; confirm Quick/Standard budgets do not exhaust before key modules.
4. Test XSS with both a vulnerable executable context and safe encoded/textarea controls.
5. Rehearse PDF output using long evidence and the actual demo data.

### Nice to have

- Add opt-in POST-form discovery and Playwright confirmation for XSS.
- Estimate request cost before starting a selected scan.
- Improve PDF wrapping/fonts/page breaks.
- Split `app.py` into route, scan-service and export modules after the demo.
- Move rate limits to Redis for multi-process deployment.

### Avoid changing before demo

- Do not rewrite the runtime, scanner result schema, or UI.
- Do not migrate SQLite or enable Redis unless the demo specifically requires it.
- Do not add broad active exploitation, brute force, or untested scanners.
- Do not change severity/CVSS/risk formulas without migrating old records and updating all views/docs.

## 11. Exact Files Likely Needed for Edits

Ask for only the smallest relevant set:

- Risk/count/status behavior: `app.py`, `templates/scan_details.html`, `static/js/dashboard-pro.js`.
- Reflected XSS: `vulnerabilities/xss.py`, `vulnerabilities/common.py`, `services/scan_runtime.py`.
- Dashboard/New Scan: `templates/dashboard.html`, `static/js/dashboard-pro.js`, and `static/css/dashboard-pro.css` only for styling.
- PDF/export: `app.py`, plus `templates/scan_details.html` for buttons.
- Persistence/schema: `database.py` and the relevant tests.
- Individual scanner: only its `vulnerabilities/<module>.py`, `vulnerabilities/common.py`, and matching test file.

Do not request `.env`, the database file, `.venv`, images, caches, or the whole repository unless a reproducible issue genuinely spans those areas.
