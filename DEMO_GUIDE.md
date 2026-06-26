# دليل عرض CyberScan في مناقشة التخرج

هذا الملف عبارة عن Checklist مختصر لاستخدامه قبل وأثناء عرض المشروع.

## قبل العرض

1. ثبّت المكتبات:

```bash
pip install -r requirements.txt
```

2. أنشئ ملف `.env` من `.env.example`.

3. ضع قيمًا آمنة للأسرار:

```env
FLASK_SECRET_KEY=your-real-secret
JWT_SECRET_KEY=your-real-jwt-secret
FLASK_DEBUG=false
```

4. إذا كنت ستعرض AI Analysis، أضف:

```env
OPENAI_API_KEY=your-openai-api-key
```

5. شغّل التطبيق:

```bash
python app.py
```

6. افتح:

```text
http://127.0.0.1:5000
```

## حساب ديمو مقترح

أنشئ الحساب التالي من صفحة Register قبل المناقشة:

```text
Email: demo@cyberscan.local
Password: Demo12345
```

## مسار العرض المقترح

1. اعرض الصفحة الرئيسية واشرح الفكرة العامة.
2. سجل الدخول بحساب الديمو.
3. افتح Dashboard.
4. ابدأ بشرح بطاقات الإحصائيات: إجمالي الفحوصات، المكتملة، الجارية، الفاشلة، إجمالي النتائج، وأعلى درجة خطورة.
5. اضغط `New Scan`.
6. أدخل هدفًا مصرحًا بفحصه.
7. اختر `Quick Scan` لتحديد الفحوصات الآمنة والسريعة تلقائيًا.
8. ابدأ الفحص.
9. اعرض الإشعارات والـ live logs.
10. اعرض النتائج في Dashboard ولاحظ تحديث الإحصائيات بعد انتهاء الفحص.
11. افتح History واعرض أن الفحص تم حفظه.
12. اضغط `View Details` على أحد الفحوصات.
13. اعرض Target URL وStatus وDate وUser وHighest Severity.
14. اعرض أن النتائج مجمعة حسب اسم Scanner.
15. اشرح Severity وOWASP Mapping وRecommendations.
16. اضغط `Download PDF Report` لعرض التقرير الاحترافي.
17. اضغط `Export JSON` لتوضيح أن النتائج قابلة للتكامل مع أدوات أخرى.
18. اعرض AI Analysis إذا كان مفتاح OpenAI مضبوطًا.

## وحدات فحص مناسبة لديمو سريع

ابدأ بهذه الوحدات لأنها عادة لا تحتاج مدخلات إضافية:

- Info Scan
- Clickjacking Scanner
- CORS Scanner
- CSRF Scan
- Dir Scan

يمكن اختيارها بسرعة من Dashboard عن طريق `Scan Mode` ثم `Quick Scan`. هذا الخيار لا يمنع الاختيار اليدوي؛ يمكن تعديل الفحوصات بعد اختياره إذا احتجت ذلك.

تجنب في بداية العرض الوحدات التي تحتاج مدخلات إضافية مثل upload endpoint أو login URL أو parameter name، إلا إذا كنت جهزت هذه القيم مسبقًا.

## ماذا تقول عن Dashboard Statistics

Dashboard لا يعرض أرقامًا ثابتة أو تجريبية. الإحصائيات تُحسب من قاعدة البيانات للفحوصات الخاصة بالمستخدم الحالي، وتشمل عدد الفحوصات، حالتها، عدد النتائج، توزيع الخطورة، وأحدث الفحوصات. هذا يثبت أن الفحص يتم حفظه ومتابعته وليس مجرد عرض مؤقت في المتصفح.

## ماذا تقول عن Quick Scan

Quick Scan هو وضع مناسب للديمو لأنه يختار فحوصات خفيفة وآمنة نسبيًا: Info Scan وClickjacking وCORS وCSRF وDir Scan. الهدف منه تقليل وقت العرض وتجنب الفحوصات التي تحتاج مدخلات إضافية. Custom/Manual Scan ما زال موجودًا لاختيار أي Scanner يدويًا.

## هدف اختبار مقترح

الأفضل استخدام هدف محلي أو بيئة تدريب تملكها. إذا احتجت هدفًا خارجيًا سريعًا قبل المناقشة، اختبر على:

```text
http://testphp.vulnweb.com
```

اختر عددًا قليلًا من الفحوصات حتى لا يستغرق العرض وقتًا طويلًا.

## فحوصات يفضل تجنبها في الديمو المباشر

تجنب هذه الفحوصات أثناء العرض إلا إذا جهزت مدخلاتها مسبقًا:

- File Upload
- GraphQL Scanner
- Stored XSS Scanner
- Auth Scanner
- Weak Password Scanner
- SQL Injection
- XSS
- SSRF
- SSRF Scanner
- IDOR
- Path Traversal

بعض هذه الفحوصات قد تكون بطيئة، وبعضها يحتاج parameter أو endpoint أو login URL.

## نص مختصر تقوله أثناء العرض

CyberScan هو مشروع لفحص ثغرات تطبيقات الويب بشكل آلي. المستخدم يسجل الدخول، يبدأ فحصًا حقيقيًا من لوحة التحكم، يختار وحدات الفحص المناسبة، ثم تظهر النتائج ويتم حفظها في قاعدة البيانات. المشروع مبني بشكل modular، لذلك يمكن إضافة أي Scanner جديد داخل مجلد vulnerabilities بدون تغيير كبير في بنية النظام.

## ماذا تقول عن صفحة Scan Details

صفحة Scan Details تحول نتائج الفحص الخام إلى عرض أوضح للمناقشة. بدل عرض النتيجة كنص فقط، الصفحة تعرض كل finding مع اسم الـ Scanner، درجة الخطورة، التصنيف حسب OWASP Top 10، الدليل أو الـ evidence إن وجد، وتوصية عملية للمطور.

## ماذا تقول عن Severity

Severity يتم توحيده إلى خمس درجات:

- Critical
- High
- Medium
- Low
- Info

إذا لم يرجع Scanner درجة خطورة واضحة، النظام يحدد قيمة افتراضية بناءً على نوع الفحص. مثلًا SQL Injection وSSRF وIDOR تعتبر High، بينما Info Scan تعتبر Info.

## ماذا تقول عن OWASP Mapping

كل نوع فحص يتم ربطه بتصنيف OWASP Top 10 المناسب. مثلًا:

- SQL Injection وXSS تحت A03: Injection.
- IDOR وPath Traversal تحت A01: Broken Access Control.
- SSRF تحت A10: Server-Side Request Forgery.
- Weak Password وAuth تحت A07: Identification and Authentication Failures.
- CORS وCSRF وClickjacking وInfo Scan تحت A05: Security Misconfiguration.

## ماذا تقول عن Recommendations

Recommendations ليست مجرد وصف للثغرة، بل خطوات عملية قصيرة للمطور. مثلًا عند SQL Injection تكون التوصية استخدام parameterized queries، وعند XSS تكون encoding وsanitization وContent Security Policy.

## ماذا تقول عن PDF Report وJSON Export

PDF Report مناسب للعرض على الدكتور لأنه يلخص الهدف، التاريخ، الحالة، عدد النتائج، أعلى خطورة، والنتائج مجمعة حسب Scanner مع OWASP والتوصيات. أما `Export JSON` فهو مخصص للتكامل التقني، حيث يحتوي على النتائج normalized مع severity distribution وOWASP categories وrecommendations.

## إذا لم تظهر Findings

إذا لم يرجع الفحص ثغرات، وضح أن هذا لا يعني أن الموقع آمن بنسبة 100%، بل يعني أن الفحوصات المختارة لم تكتشف مشاكل ضمن نطاقها. يمكن ذكر أن تقليل false positives مهم، وأن المشروع يعرض "No findings" بشكل واضح بدل اختراع نتائج غير حقيقية.

## ملاحظات مهمة أثناء المناقشة

- استخدم أهدافًا مصرحًا بفحصها فقط.
- اجعل `FLASK_DEBUG=false`.
- لا تعرض ملف `.env` الحقيقي.
- اختبر الهدف المختار قبل يوم المناقشة.
- اختر عددًا قليلًا من Scanners حتى يكون الديمو سريعًا.

## إذا حدثت مشكلة أثناء العرض

- إذا فشل تسجيل الدخول، أنشئ حساب ديمو جديد.
- إذا فشل AI Analysis، وضح أنه يعتمد على `OPENAI_API_KEY` وأكمل عرض النتائج الأساسية.
- إذا أعطى Scanner خطأ، وضح أن كل Scanner يعمل بشكل مستقل وأن النظام يسجل أخطاء الوحدات بدون إيقاف الفحص كاملًا.
- إذا كان الفحص بطيئًا، اختر عددًا أقل من وحدات الفحص وأعد التشغيل.
- إذا فشل الفحص المباشر بسبب الإنترنت، افتح History واعرض فحصًا محفوظًا مسبقًا.
