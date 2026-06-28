# دليل عرض CyberScan Professional 5.0

## عرض سريع أمام اللجنة

1. افتح Dashboard واختر **Modern App Scan**.
2. اعرض وحدات SPA وOpenAPI وGraphQL وWebSocket وgRPC وAuthorization Matrix وOIDC.
3. وضح أن JavaScript ينفذ داخل Chromium، مع منع POST/PUT/DELETE افتراضيًا.
4. أدخل حسابي اختبار منخفض وعالي الصلاحية في Auth Profiles.
5. ابدأ الفحص داخل المختبر المصرح به واعرض Progress وCurrent Scanner وRequest Count.
6. افتح Modern Artifacts واعرض الصفحات وطلبات Fetch وعمليات API وأنواع GraphQL.
7. صدّر Sanitized HAR وأظهر أن Headers وBodies وTokens غير موجودة.
8. افتح Finding واعرض Confidence وEvidence وOWASP وASVS وCWE وCVSS.
9. اعرض SARIF للتكامل مع CI/CD.
10. اعرض Redis mode كخيار توسع، مع Encrypted queue وWorker heartbeat.

## نقاط دفاع تقنية

- لا يعتبر تفعيل GraphQL Introspection ثغرة مؤكدة وحده.
- لا ينفذ WebSocket messages أو gRPC business calls تلقائيًا.
- OpenAPI probes مقتصرة افتراضيًا على GET وHEAD وOPTIONS.
- Role Matrix يقارن حسابات اختبار مصرح بها ولا يخمن Credentials.
- OIDC scanner يراجع Metadata ولا يحاول اختطاف Login flow.
- الأسرار تظل في الذاكرة أو داخل Redis مشفرة، ولا تدخل التقارير.
- 54/54 تعني نجاح الاختبارات المرفقة، وليس ضمانًا مطلقًا لكل تطبيق.
