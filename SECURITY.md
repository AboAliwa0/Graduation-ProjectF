# سياسة الأمان والاستخدام — CyberScan 5.0

## الاستخدام المسموح

استخدم المنصة فقط على تطبيق تملكه، مختبر معزول، أو هدف لديك تصريح كتابي صريح لاختباره. حدد النطاق والوقت والحسابات المسموح بها قبل التشغيل.

## الوضع الآمن الافتراضي

- Private وLoopback وLink-local وReserved وCloud metadata محظورة.
- كل Redirect يعاد التحقق منه.
- بيانات المصادقة لا تعبر إلى Origin مختلف.
- Browser crawler يمنع Cross-origin وState-changing methods افتراضيًا.
- OpenAPI ينفذ Safe methods فقط.
- WebSocket وgRPC يعملان كجرد دون رسائل أو Business RPCs.
- لكل Scan Request budget وحد حجم استجابة وحد زمني وإلغاء.
- النتائج غير المؤكدة تصنف Potential أو Inconclusive.

## الأسرار

- لا ترفع `.env` أو `data/` أو Playwright storage state إلى Git.
- استخدم حسابات اختبار لا حسابات أشخاص حقيقيين.
- Storage State وAuth Profiles وHeaders وCookies لا تحفظ في DB أو التقارير.
- في Redis mode، مهام الطابور مشفرة بـ`QUEUE_ENCRYPTION_KEY`.
- تغيير مفتاح Queue أثناء وجود Jobs معلقة يجعلها غير قابلة للفك.
- ألغِ أي API key ظهر سابقًا في Git history؛ تنظيف الملف لا يلغي المفتاح من مزوده.

## إعدادات خطرة على خادم عام

```env
ALLOW_PRIVATE_TARGETS=true
ALLOW_INSECURE_TLS=true
FLASK_DEBUG=true
ALLOW_UNSAFE_WERKZEUG=true
```

## Redis mode

- ضع Redis على شبكة داخلية ولا تعرضه للإنترنت.
- فعّل مصادقة/TLS لRedis خارج شبكة Docker المحلية.
- حافظ على `QUEUE_ENCRYPTION_KEY` في Secret Manager.
- Workers يستعملون Heartbeat؛ المهام المتروكة تعاد للطابور.
- SQLite تعمل للعرض والفريق الصغير، لكن PostgreSQL أفضل للتوسع الأفقي العالي.

## حدود معروفة

- لا يوجد إثبات آلي كامل لـBusiness Logic أو Race Conditions.
- DOM-based flows المعقدة قد تحتاج تحليلًا يدويًا.
- OIDC لا يجرب Login/Redirect exploitation تلقائيًا.
- WebSocket/gRPC default inventory لا يختبر رسائل تغير الحالة.
- Rate limiting الخاص بتسجيل الدخول داخل Process في الوضع المحلي؛ استخدم Gateway/Redis policy في نشر متعدد النسخ.
- CSP للواجهة تسمح حاليًا بـInline script؛ انقل JavaScript إلى static files واستخدم Nonce قبل بيئة عالية الحساسية.

## الإبلاغ

لا ترفق أسرارًا أو بيانات هدف حقيقي. أرسل خطوات إعادة إنتاج داخل مختبر مع رقم الإصدار من `VERSION`.
