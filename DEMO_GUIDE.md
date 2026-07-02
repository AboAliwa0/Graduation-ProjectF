# CyberScan Graduation Demo Guide

Use CyberScan only against a target owned by the project team or explicitly authorized by the instructor.

## Before the Demo

1. Activate the project virtual environment and start CyberScan.
2. Confirm that `.env` contains valid local secrets and safe target settings.
3. Confirm that the instructor target is reachable and explicitly authorized.
4. Keep a previously generated PDF and JSON report in `reports/final_target_scan/` as a backup.

## Demo Flow

1. Open `http://127.0.0.1:5000` and log in with the prepared demo account.
2. Open **New Scan** from the Dashboard and keep the default **Quick** preset.
3. Enter the authorized instructor target URL.
4. Check the authorization confirmation box.
5. Select the demo-safe modules:
   - Information Disclosure
   - CORS Misconfiguration
   - Clickjacking Protection
   - Host Header Injection
   - CSRF Form Protection
6. Keep TLS verification enabled. Use a request budget appropriate for the instructor target.
7. Start the scan and show live status, current module, progress, and request count.
8. Explain that only `confirmed` and `potential` results count as security findings. Scanner errors and inconclusive checks are operational results and appear separately.
9. Open **Scan Details** and show severity, confidence, evidence, OWASP/ASVS mapping, CWE/CVSS, and recommendations.
10. Explain the Risk Score using this sentence: "Aggregate risk score based on severity, confidence, and finding status. It is different from CVSS."
11. Download the PDF report and JSON export from Scan Details.
12. Place the final demo exports in `reports/final_target_scan/` using clear filenames such as:
    - `cyberscan-final-target-report.pdf`
    - `cyberscan-final-target-results.json`

## Report Talking Points

- **Executive Summary:** gives the finding count, highest severity, and aggregate risk.
- **Target Information:** identifies the authorized target, user, date, and scan status.
- **Scan Configuration:** records scan mode, selected scanners, request usage, and tool version.
- **Findings Summary:** counts only confirmed and potential security findings.
- **Detailed Findings:** provides evidence, confidence, mappings, and remediation guidance.
- **Scanner Errors / Inconclusive Checks:** records operational limitations without inflating vulnerability totals.
- **Limitations:** explains that automated scanning cannot prove complete security.
- **Recommendations:** provides practical remediation actions from detected findings.

## Backup Plan

If the live target or network is unavailable, open the latest completed Scan Details record and present the saved PDF and JSON files from `reports/final_target_scan/`. Do not switch to an unauthorized public target during the discussion.

## Final Safety Reminder

Never scan a system without explicit authorization. Avoid authentication, upload, stored-XSS, SSRF, blind-XSS, and deep browser modules during the live discussion unless the instructor prepared an isolated lab and supplied the required inputs.

Do not enable IDOR, Authorization Matrix, Login Abuse, Weak Credential, File Upload, Stored XSS, SSRF, Blind XSS, or gRPC during the live demo unless the instructor supplied the exact authorized endpoint, account/profile, and required inputs. CyberScan does not claim to detect every vulnerability; automated results still require professional validation.
