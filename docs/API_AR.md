# API — CyberScan 5.0

## المصادقة

- Session: يحتاج CSRF للطلبات المغيرة.
- API: `POST /api/login` ثم:

```http
Authorization: Bearer <short-lived-jwt>
```

## Scanner catalog

```http
GET /api/scanners
```

يعيد 26 وحدة ومدخلاتها الديناميكية.

## بدء فحص

```http
POST /scan-live
Content-Type: application/json
```

الحقول:

- `url`: هدف مصرح به.
- `vulns`: scanner IDs.
- `authorized`: يجب أن تكون `true`.
- `scan_mode`: standard/modern.
- `request_budget`.
- `verify_tls`.
- `scanner_inputs`.
- `http_headers` و`cookies`: أسرار مؤقتة غير مخزنة.
- `auth_profiles`: حتى 4 Profiles.
- `browser_storage_state`: Playwright state مؤقت.

مثال Auth profile:

```json
{
  "name": "user-test",
  "expected_access": "user",
  "headers": {"Authorization": "Bearer test-token"},
  "cookies": {"session": "test-session"}
}
```

## المتابعة

- `GET /scan-status/<id>`
- `POST /scan/<id>/cancel`

الحالات: queued، running، done، cancelling، cancelled، budget_exhausted، failed، interrupted.

## Scopes

- `GET /api/scopes`
- `POST /api/scopes`
- `DELETE /api/scopes/<id>`

## التصدير

- PDF: `/scan/<id>/report`
- JSON: `/scan/<id>/export-json`
- SARIF 2.1.0: `/scan/<id>/export-sarif`
- Modern artifacts: `/scan/<id>/export-artifacts`
- Sanitized HAR: `/scan/<id>/export-har`

HAR لا يحتوي request/response bodies أو headers أو cookies أو tokens.

## التدقيق والصحة

- `GET /api/audit`
- `GET /health`

`/health` يعيد الإصدار، queue backend، والخصائص الحديثة المفعلة.
