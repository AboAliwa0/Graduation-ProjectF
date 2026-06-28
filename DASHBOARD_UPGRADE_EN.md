# Professional Dashboard Upgrade

A new English CyberScan Professional 5.0 dashboard has been added with separate frontend files:

- `templates/dashboard.html`
- `static/css/dashboard-pro.css`
- `static/js/dashboard-pro.js`

## Highlights

- Executive risk overview with a live Risk Score indicator and severity distribution.
- Recent scans list with progress, current status, and selected target summary.
- Searchable and filterable findings table with a details modal for each finding.
- Fast export center for PDF, JSON, SARIF, Artifacts, and Sanitized HAR.
- New scan modal connected to `/scan-live` with Quick, Standard, Modern, and Deep modes.
- Support for scanner inputs, HTTP headers, cookies, auth profiles, and Playwright Storage State.
- Target Scope management from the same interface.
- Recent scanner module overview and latest audit events.

## Run

Use the original run commands.

### Windows

```bat
setup_and_run.bat
```

### Linux / macOS

```bash
chmod +x setup_and_run.sh
./setup_and_run.sh
```

Then open:

```text
http://127.0.0.1:5000
```

> Only scan assets you own or have clear written authorization to test.
