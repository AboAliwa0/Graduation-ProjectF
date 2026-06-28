# ملاحظات الإصدار 5.0.0

## دعم التطبيقات الحديثة

- Playwright Chromium لتنفيذ JavaScript واكتشاف SPA وFetch وXHR وWebSocket.
- OpenAPI 2.0 و3.x، بما في ذلك 3.2.0، مع JSON/YAML وLocal `$ref`.
- GraphQL schema inventory بدل اختبار Introspection سطحي فقط.
- WebSocket Handshake inventory آمن.
- gRPC Server Reflection inventory.
- OAuth 2.0 / OIDC discovery assessment.
- Auth Profiles متعددة ومقارنة صلاحيات بين أدوار اختبارية.
- Playwright Storage State لجلسات الاختبار المصرح بها.

## التشغيل والإنتاج

- Queue محلي محدود أو Redis موزع اختياري.
- تشفير مهام Redis بـFernet، بما فيها بيانات الجلسة المؤقتة.
- Processing queues وWorker heartbeat واستعادة مهام العامل المتوقف.
- إلغاء موزع للفحص.
- Socket.IO message queue اختيارية عبر Redis.
- حفظ Artifacts وتصدير HAR منقح دون أسرار.

## الدقة والتقارير

- 26 Scanner/Discovery modules.
- ربط النتائج بفئات ASVS 5.0 بالإضافة إلى OWASP وCWE وCVSS.
- تصنيف Introspection وCSRF indicators وHost body reflection كـPotential عند غياب إثبات مباشر.
- تحليل سياق HTML لمنع اعتبار Script داخل `textarea` أو `template` تنفيذًا فعليًا.
- OpenAPI وBrowser وGraphQL وAuthorization وOIDC artifacts في صفحة الفحص.

## إصلاحات

- لا تظهر الحالة `done` في قاعدة البيانات إلا بعد انتهاء Audit وSocket events، لتجنب اعتبار Thread ما زال يعمل مهمة مكتملة.
- Redis mode لا يحول Queued jobs إلى `interrupted` عند إعادة تشغيل Web process.
- Request budget والإلغاء ينتقلان عبر جميع الوحدات دون التحول إلى Scanner error.
- الردود الكبيرة تقطع أثناء Streaming.
- منع انتقال Authorization/Cookies إلى Origin مختلف.

## التحقق

- Pytest: **54/54 ناجحًا**.
- اختبارات حقيقية لـChromium وWebSocket وgRPC Reflection.
- Python compile: ناجح.
- Dashboard JavaScript syntax: ناجح.
- الحزمة النهائية لا تحتوي `.env` أو Database أو Git history أو API keys.
