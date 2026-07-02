# CyberScan Professional 5.0

منصة **Modern DAST منخفضة التأثير** لفحص تطبيقات الويب وواجهات API التي تملكها أو لديك تصريح كتابي واضح لاختبارها. يركز الإصدار 5.0 على التطبيقات الحديثة، جودة الدليل، ومنع النتائج الكاذبة، مع تشغيل آمن افتراضيًا.

> لا توجد أداة آلية تستطيع إثبات أمان كل تطبيق بنسبة 100%. الرقم 100% في هذا الإصدار يعني نجاح جميع اختبارات الحزمة المرفقة، وليس تغطية كل ثغرة أو كل منطق أعمال ممكن.

## حالة الإصدار

- **26 وحدة فحص واكتشاف**.
- **140 اختبارًا آليًا** تشمل الحالات المصابة والسليمة ومحرك المتصفح وAPI والطابور الموزع وحدود الأمان.
- متصفح Chromium حقيقي عبر Playwright لتطبيقات React وAngular وVue وSPA.
- OpenAPI 2.0 و3.x، بما في ذلك 3.2.0.
- GraphQL schema inventory، WebSocket handshake inventory، وgRPC Reflection inventory.
- OAuth 2.0 / OpenID Connect discovery assessment.
- مقارنة صلاحيات بين حسابات اختبار متعددة.
- تشغيل محلي بـThread pool أو تشغيل موزع اختياري عبر Redis مع تشفير مهام الطابور.
- تصدير PDF وJSON وSARIF وArtifacts وHAR منقح.
- ربط النتائج بـOWASP Top 10 وفئات ASVS 5.0.
- الإعداد الافتراضي للعرض هو **Quick Scan** منخفض التأثير، ولا يختار وحدات الإعداد الخاص تلقائيًا.

تُحسب النتائج ذات الحالة `confirmed` أو `potential` فقط كثغرات أمنية. حالات `error` و`inconclusive` نتائج تشغيلية منفصلة ولا ترفع عدد الثغرات. كما أن **Risk Score تجميعي داخلي وليس CVSS**.

## إمكانات التطبيقات الحديثة

### متصفح حقيقي وآمن افتراضيًا

`modern_spa_scanner` يقوم بما يلي:

- تنفيذ JavaScript داخل Chromium Headless.
- اكتشاف مسارات SPA والروابط والنماذج.
- تسجيل طلبات Document وXHR وFetch وWebSocket.
- اكتشاف مؤشرات React وAngular وVue وSvelte وNuxt.
- استخدام Playwright Storage State لجلسة اختبار مصرح بها.
- منع الطلبات التي تغير الحالة مثل POST وPUT وDELETE افتراضيًا.
- منع الاتصالات الخارجية عن نطاق الهدف افتراضيًا.
- احتساب طلبات المتصفح ضمن Request Budget.
- حد زمني للانتقال وعدد أقصى للصفحات.

### OpenAPI وAPI Discovery

- استيراد JSON أو YAML.
- دعم Swagger/OpenAPI 2.0 وكل إصدارات OpenAPI 3.x.
- حل `$ref` المحلي مع منع الدوران.
- منع External References افتراضيًا.
- التحقق من أن Servers تبقى داخل النطاق المصرح به.
- جرد Methods وParameters وSecurity Requirements.
- تنفيذ GET وHEAD وOPTIONS فقط في الوضع الآمن.
- تنبيه عند Endpoint حساس يبدو غير محمي في العقد.

### GraphQL وWebSocket وgRPC

- GraphQL: جرد Query وMutation وSubscription والأنواع عند السماح بالـIntrospection؛ تفعيل Introspection وحده يصنف `potential` لا `confirmed`.
- WebSocket: فحص Handshake آمن فقط، دون إرسال رسائل تطبيق أو Fuzzing تلقائي.
- gRPC: استخدام Server Reflection لجرد الخدمات وملفات Descriptors فقط، دون استدعاء Business RPCs.

### المصادقة والصلاحيات الحديثة

- Headers وCookies عامة داخل الذاكرة فقط.
- Playwright Storage State دون حفظه في قاعدة البيانات أو التقارير.
- حتى 4 Auth Profiles بحسابات اختبار مختلفة.
- مقارنة Role Matrix على Endpoints آمنة ومصرح بها.
- جرد OIDC Discovery والتحقق من HTTPS وPKCE S256 وخوارزمية `none` وLegacy implicit flows.
- إزالة Authorization وCookies عند الانتقال إلى Origin مختلف.

## حالات النتائج

| الحالة | معناها |
|---|---|
| `confirmed` | الوحدة رصدت دليلًا مباشرًا وفق معيارها المحدد. |
| `potential` | مؤشر أمني يحتاج مراجعة يدوية. |
| `not_vulnerable` | لم يظهر المؤشر في السيناريو المنفذ. |
| `inconclusive` | لم تتوفر شروط كافية للحكم. |
| `error` | تعذر إكمال الوحدة. |

لكل نتيجة: Severity وConfidence وEvidence وEndpoint وParameter وCWE وCVSS وOWASP وASVS وتوصية إصلاح.

## ضوابط التنفيذ

- تأكيد التفويض إلزامي لكل فحص.
- Target Scope لكل مستخدم، وقائمة سماح مركزية اختيارية.
- Private وLoopback وLink-local وCloud metadata محظورة افتراضيًا.
- DNS وRedirects يعاد التحقق منها.
- Request Budget صلب، وحد لحجم الاستجابة، وحد زمني.
- حفظ النتائج الجزئية عند الإلغاء أو نفاد الميزانية.
- عزل Socket.IO لكل مستخدم وفحص.
- الأسرار لا تكتب في DB أو Audit أو PDF أو JSON أو HAR.
- HAR المصدّر لا يحتوي Headers أو Bodies أو Cookies أو Tokens.

## التشغيل السريع

### Windows

```bat
setup_and_run.bat
```

### Linux / macOS

```bash
chmod +x setup_and_run.sh
./setup_and_run.sh
```

ثم افتح:

```text
http://127.0.0.1:5000
```

سكريبت الإعداد ينشئ Virtual Environment، يثبت المتطلبات ومتصفح Chromium الخاص بـPlaywright، ثم يولد أسرارًا محلية.

## التشغيل باستخدام Docker — وضع محلي

```bash
cp .env.example .env
python scripts/generate_secrets.py
docker compose up --build
```

## التشغيل الموزع باستخدام Redis

هذا الوضع مناسب عند فصل الواجهة عن Workers:

```bash
cp .env.example .env
python scripts/generate_secrets.py
docker compose -f docker-compose.redis.yml up --build
```

الخصائص:

- مهام الطابور مشفرة باستخدام Fernet.
- العامل يستخدم Processing Queue وHeartbeat.
- مهمة العامل المتوقف تعاد تلقائيًا إلى الطابور بعد انتهاء Heartbeat.
- الإلغاء موزع عبر Redis.
- Socket.IO يمكنه استخدام Redis message queue.

القيم الأساسية:

```env
SCAN_QUEUE_BACKEND=redis
REDIS_URL=redis://redis:6379/0
SOCKETIO_MESSAGE_QUEUE=redis://redis:6379/1
QUEUE_ENCRYPTION_KEY=<generated-fernet-key>
```

لا تشارك `QUEUE_ENCRYPTION_KEY` ولا تغيره بينما توجد مهام مشفرة معلقة.

## إعداد إنتاج مقترح

```env
SESSION_COOKIE_SECURE=true
ENABLE_HSTS=true
ALLOW_PRIVATE_TARGETS=false
ALLOW_INSECURE_TLS=false
ALLOW_UNSAFE_WERKZEUG=false
REQUIRE_TARGET_SCOPE=true
SCAN_ALLOWED_HOSTS=example.com,*.staging.example.com
SOCKET_ALLOWED_ORIGINS=https://scanner.example.com
```

ضع المنصة خلف HTTPS Reverse Proxy. استخدم PostgreSQL وخدمة OAST منفصلة عند الأحمال أو الفرق الكبيرة؛ SQLite مناسبة للعرض والفريق الصغير.

## مثال Modern Scan

```json
{
  "url": "https://app.example.com/",
  "vulns": [
    "modern_spa_scanner",
    "openapi_scanner",
    "graphql_scanner",
    "websocket_scanner",
    "authorization_matrix_scanner",
    "oidc_scanner"
  ],
  "authorized": true,
  "scan_mode": "modern",
  "request_budget": 150,
  "verify_tls": true,
  "scanner_inputs": {
    "modern_spa_scanner": {"max_pages": 8, "navigation_timeout_ms": 12000},
    "openapi_scanner": {"document_url": "/openapi.json", "probe_limit": 20},
    "graphql_scanner": {"endpoint": "/graphql"},
    "authorization_matrix_scanner": {"endpoints": "/api/admin,/api/profile", "max_endpoints": 10},
    "oidc_scanner": {"discovery_url": "/.well-known/openid-configuration"}
  },
  "auth_profiles": [
    {
      "name": "user-test",
      "expected_access": "user",
      "headers": {"Authorization": "Bearer authorized-low-role-token"}
    },
    {
      "name": "admin-test",
      "expected_access": "admin",
      "headers": {"Authorization": "Bearer authorized-admin-test-token"}
    }
  ],
  "browser_storage_state": {"cookies": [], "origins": []}
}
```

استخدم حسابات اختبار فقط، ولا تستخدم حسابًا شخصيًا أو حساب إنتاج عالي الصلاحيات.

## API والتصدير

- `POST /scan-live`
- `GET /scan-status/<id>`
- `POST /scan/<id>/cancel`
- `GET /scan/<id>/report`
- `GET /scan/<id>/export-json`
- `GET /scan/<id>/export-sarif`
- `GET /scan/<id>/export-artifacts`
- `GET /scan/<id>/export-har`
- `GET /api/audit`

## الاختبارات

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

النتيجة المسجلة للإصدار:

```text
140 passed
```

تغطي الاختبارات:

- الوحدات التقليدية بحالات إيجابية وسلبية.
- Chromium حقيقي وSPA وFetch/XHR.
- OpenAPI 3.1 و3.2 وSafe probes.
- GraphQL schema inventory.
- WebSocket server حقيقي.
- gRPC Reflection server حقيقي.
- OIDC secure/risky metadata.
- Role separation الإيجابية والسلبية.
- Redis queue encryption وFIFO وCancellation واستعادة عامل متوقف.
- End-to-End من API إلى DB والتقارير مع التأكد من عدم تسريب الأسرار.
- Python compile وJavaScript syntax وفحص الحزمة.

## حدود صريحة

- Business Logic وRace Conditions وسلاسل الصلاحيات المعقدة تحتاج مختبرًا يدويًا.
- DOM XSS الكامل يحتاج Taint Tracking أو تحليل يدوي أعمق.
- WebSocket وgRPC في الوضع الافتراضي Inventory فقط حتى لا يغيّرا بيانات التطبيق.
- OIDC scanner لا يجرب تسجيل دخول أو اختطاف Redirect URI تلقائيًا.
- وحدات IDOR وAuthorization Matrix وLogin Abuse وWeak Credential وFile Upload وStored XSS وSSRF وBlind XSS وgRPC تحتاج مدخلات مختبرية صريحة من المدرس ولا تُستخدم تلقائيًا في العرض.
- نجاح 140/140 لا يعني ضمان اكتشاف كل ثغرة في كل تطبيق.

راجع `SECURITY.md` و`TEST_REPORT_AR.md` و`docs/ARCHITECTURE_AR.md` و`docs/SCANNER_MATRIX_AR.md`.
