# معمارية CyberScan Professional 5.0

## تدفق الفحص

1. مصادقة المستخدم عبر Session أو JWT.
2. التحقق من CSRF لطلبات Session.
3. التحقق من `authorized=true` وURL وDNS وServer allowlist وTarget scope.
4. إنشاء Scan record دون حفظ أي Credential.
5. إنشاء Runtime يحتوي Request budget وHTTP session وAuth context وArtifacts.
6. التنفيذ بأحد وضعين:
   - `local`: ThreadPoolExecutor محدود.
   - `redis`: Job مشفر، Worker مستقل، Processing list، Heartbeat، وRecovery.
7. كل طلب HTTP أو Browser tracked request يستهلك من الميزانية.
8. يتم تحديث Progress وCurrent Scanner والنتائج الجزئية.
9. تحفظ Artifacts المنقحة في DB بحد حجم.
10. ينفذ Audit وSocket events، ثم تحفظ الحالة النهائية آخرًا.

## طبقات المشروع

- `app.py`: Web/API/Auth/Reports/Orchestration.
- `database.py`: SQLite schema وMigration وAudit.
- `worker.py`: Redis worker مستقل.
- `services/scan_runtime.py`: Context وBudget وCancellation وSession.
- `services/scan_manager.py`: Local bounded executor.
- `services/distributed_queue.py`: Redis encrypted reliable queue.
- `services/browser_crawler.py`: Chromium SPA crawler.
- `services/api_discovery.py`: OpenAPI parser وsafe probes.
- `services/graphql_support.py`: GraphQL schema inventory.
- `services/websocket_support.py`: WebSocket handshake.
- `services/grpc_support.py`: gRPC reflection.
- `services/auth_profiles.py`: Auth profiles parsing/redaction.
- `vulnerabilities/*.py`: 26 وحدات فحص واكتشاف.
- `services/oast.py`: Callback verification لـSSRF وBlind XSS.

## Redis reliable queue

```text
Main queue --BRPOPLPUSH--> worker processing list
     ^                              |
     |---------- recover -----------|
```

- Payload مشفر بـFernet.
- لكل Worker processing list وHeartbeat TTL.
- Worker آخر يعيد Jobs من Processing list إذا انتهى Heartbeat.
- Job لا يحذف من Processing إلا بعد انتهاء `run_scan`.
- Cancellation key يفحص قبل كل Scanner/Request.

## Modern browser flow

```text
Authorized URL
   -> Chromium context
   -> same-origin route guard
   -> read-only method guard
   -> page/navigation limit
   -> Document/XHR/Fetch/WebSocket inventory
   -> sanitized artifact/HAR
```

Storage State وHeaders يدخلان Browser Context فقط ولا يظهران في Artifacts.

## حالات المهمة

- `queued → running → done`
- `queued/running → cancelling → cancelled`
- `running → budget_exhausted`
- `running → failed`
- Local restart: `queued/running → interrupted`
- Redis restart: Queued jobs تبقى؛ abandoned processing jobs تعاد بواسطة Heartbeat recovery.

## نموذج النتيجة

```json
{
  "name": "authorization_matrix_scanner",
  "vulnerable": true,
  "status": "potential",
  "severity": "High",
  "confidence": "Medium",
  "result": "Low and high role received highly similar successful responses.",
  "evidence": {},
  "recommendation": "Enforce server-side object and function authorization.",
  "endpoint": "https://app.example/api/admin",
  "parameter": "",
  "cwe": "CWE-862",
  "cvss": 7.5,
  "requests_made": 2
}
```

OWASP وASVS يضافان عند العرض والتصدير.

## التوسع التالي

لأحمال كبيرة:

- PostgreSQL بدل SQLite.
- Redis TLS/Auth أو Managed Redis.
- OAST service منفصلة.
- Central rate limiting في Gateway.
- CSP nonce وStatic JavaScript.
- Object storage للArtifacts الكبيرة.
