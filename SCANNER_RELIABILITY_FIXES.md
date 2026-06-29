# Scanner Reliability Fixes

This batch changes scanner reliability only. It does not change the UI, database, runtime, risk formula, or result schema.

| Scanner file | Bug fixed | Before | After | Safe test |
|---|---|---|---|---|
| `vulnerabilities/sql_injection.py` | Boolean differential was implicitly confirmed | DB errors and boolean differences both returned `confirmed` | New DB-specific errors remain `confirmed`; boolean-only evidence returns `potential` with a classification reason | Use an authorized lab with a stable `id` parameter, one DB-error endpoint, and one boolean-differential endpoint |
| `vulnerabilities/cors_scanner.py` | Simple origin reflection could be over-classified | Any reflected origin produced a vulnerable result with default confirmed status | Confirmed requires credentials plus a successful sensitive/protected-looking response; weaker reflection/preflight is `potential`; invalid wildcard-with-credentials is informational | Test a public CORS response, a credentialed private-data response, and a strict allowlist response |
| `vulnerabilities/clickjacking_scanner.py` | API/JSON endpoints could be flagged for missing framing headers | Every response was assessed as frameable content | Only successful HTML/XHTML pages are assessed; other responses are `inconclusive` with status/content-type evidence | Compare an HTML page without protection, protected HTML, JSON, and an HTTP error |
| `vulnerabilities/path_traversal.py` | A pre-encoded probe was encoded again by the query helper | `%2f` became `%252f` | Only raw traversal values are supplied and encoded once; canary behavior is unchanged | Prefer a lab canary path and expected marker; also test a safe endpoint |
| `vulnerabilities/file_upload.py` | Missing upload URL fell back to the base target | Scanner could POST to the base URL despite a missing required input | Missing upload URL or file-field name returns `inconclusive` with `upload_attempted: false` | First omit each required input; then use an isolated upload/retrieval lab with a harmless HTML marker |
| `vulnerabilities/ssrf_scanner.py` | Short OAST silence was treated as a safe result | No callback returned `not_vulnerable` | No callback returns `inconclusive`, records the observation window, and explains external setup requirements | Use a reachable CyberScan OAST callback and test both callback and no-callback endpoints |
| `vulnerabilities/info_scan.py` | Secret-like values could be stored verbatim in evidence | Matched values were copied into `sample` | Secret-like matches are masked and SHA-256 hashed; evidence retains pattern type and location | Return a fake AWS-style key/private-key header from a local lab and verify the raw value is absent from results |

## Verification

- Parse/import every scanner module.
- Run scanner tests when `requirements.txt` and `requirements-dev.txt` are installed.
- Confirm cancellation and request-budget exceptions continue to propagate unchanged.
- Confirm all changed results retain the existing common result fields.
