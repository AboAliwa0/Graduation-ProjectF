# خطة اختبار CyberScan على TryHackMe

استخدم هذه الخطة فقط مع Rooms مخصصة للتدريب داخل TryHackMe وبعد تشغيل اتصال الـ VPN أو AttackBox. لا تفحص أي IP أو نطاق خارج الـ Room أو خارج التصريح الواضح.

## المتطلبات

- حساب TryHackMe وRoom فعالة توفر Target IP أو Target URL.
- اتصال OpenVPN الخاص بـ TryHackMe على نفس الجهاز الذي يشغل CyberScan، أو تشغيل CyberScan داخل بيئة يمكنها الوصول للهدف.
- تأكيد أن الهدف يفتح من المتصفح أو عبر طلب HTTP بسيط قبل بدء الفحص.
- تشغيل CyberScan من `http://127.0.0.1:5000`.

## اختيار Room مناسبة

ابدأ بـ Room فيها تطبيق ويب واضح مثل OWASP-style labs أو Web fundamentals. الهدف الأفضل لاختبار التقارير هو صفحة ويب لديها نماذج بحث أو تسجيل دخول تجريبية أو إعدادات HTTP ظاهرة.

تجنب في أول تشغيل:

- Rooms مخصصة للاستغلال العنيف أو privilege escalation فقط.
- أي Room تطلب brute force واسع أو exploitation خارج تطبيق الويب.
- أهداف فيها أكثر من خدمة غير ويب إلا لو مطلوب اختبار service discovery بشكل منفصل ومصرح.

## إعداد الهدف

1. شغل TryHackMe VPN أو AttackBox.
2. ابدأ الـ Room وانتظر ظهور الـ Target IP.
3. افتح الهدف في المتصفح، مثال:

```text
http://10.10.x.x/
```

4. في CyberScan، أضف الهدف كما يظهر في الـ Room.
5. علم خانة التأكيد أن الهدف مصرح به.

## فحص أول منخفض التأثير

استخدم هذه الوحدات كبداية:

- `info_scan`
- `cors_scanner`
- `clickjacking_scanner`
- `host_header_scanner`
- `csrf_scan`
- `dir_scan`

إعدادات مقترحة:

```json
{
  "scan_mode": "standard",
  "request_budget": 80,
  "verify_tls": false
}
```

استخدم `verify_tls=false` فقط مع أهداف TryHackMe التي تعمل على HTTP أو شهادات تدريبية. لا تستخدمه كإعداد إنتاجي.

## فحص موجه حسب الصفحة

بعد معرفة المسارات والباراميترات من الفحص الأول، شغل وحدات موجهة:

- `xss` على URL فيه query parameter مثل `/search?q=test`.
- `sql_injection` على parameter مصرح داخل اللاب.
- `open_redirect_scanner` على parameter redirect مصرح.
- `path_traversal` فقط لو الـ Room فيها endpoint مخصص لذلك.

مثال هدف موجه:

```text
http://10.10.x.x/search?q=test
```

## وحدات لا تشغلها إلا بتجهيز واضح

لا تشغل الوحدات التالية إلا إذا الـ Room صرحت بها وقدمت endpoint أو بيانات اختبار:

- `weak_password_scanner`
- `auth_scanner`
- `idor`
- `authorization_matrix_scanner`
- `file_upload`
- `stored_xss_scanner`
- `ssrf_scanner`
- `blind_xss`
- `grpc_scanner`

## التحقق من النتائج

بعد انتهاء الفحص:

1. افتح Scan Details.
2. راجع فقط حالات `confirmed` و`potential` كـ findings.
3. افصل `error` و`inconclusive` كتشغيل غير مكتمل وليس كثغرات.
4. قارن evidence مع سلوك الهدف داخل الـ Room.
5. صدر PDF وJSON من صفحة التفاصيل.
6. ضع النسخ النهائية في:

```text
reports/final_target_scan/
```

أسماء مقترحة:

```text
tryhackme-room-name-report.pdf
tryhackme-room-name-results.json
```

## بيانات نحتاجها لتشغيل تجربة فعلية

أرسل للفريق:

- اسم الـ Room.
- Target IP أو URL.
- هل يعمل HTTP أم HTTPS.
- أي endpoint معروف للاختبار مثل `/search?q=test`.
- أي بيانات تسجيل دخول تجريبية يوفرها اللاب.
- قائمة الوحدات التي تريد اختبارها في التقرير النهائي.
