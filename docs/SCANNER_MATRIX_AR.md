# مصفوفة وحدات CyberScan 5.0

## الوحدات الحديثة

| الوحدة | الوظيفة | الحكم الآلي الافتراضي |
|---|---|---|
| Modern SPA | Chromium، SPA routes، forms، Fetch/XHR، framework hints | Inventory / Inconclusive عند تعذر المتصفح |
| OpenAPI | OpenAPI 2 و3.x، operations، security، safe probes | Potential عند عقد حساس بلا حماية معلنة |
| GraphQL | Schema وQuery/Mutation/Subscription inventory | Introspection = Potential وليس Confirmed |
| WebSocket | Handshake وTLS/Origin metadata | Inventory؛ الاتصال وحده ليس ثغرة |
| gRPC | Reflection services وdescriptors | Reflection exposure = Potential حسب السياق |
| Authorization Matrix | مقارنة حسابات اختبار على GET endpoints | Highly similar access = Potential |
| OAuth/OIDC | Discovery metadata، HTTPS، PKCE، algs، flows | HTTP/unsigned alg قوي؛ hardening gaps Potential |

## الوحدات الأساسية

| الوحدة | شرط الإثبات | الحكم |
|---|---|---|
| Clickjacking | غياب XFO الفعال وCSP frame-ancestors | Confirmed |
| CORS | انعكاس Origin غير موثوق مع تقييم credentials | Confirmed عند الدليل |
| CSRF | Form مغير للحالة بلا Token ظاهر | Potential |
| Directory Listing | `Index of` وروابط متعددة | Confirmed |
| Information Disclosure | Stack trace أو secret pattern | Confirmed؛ headers وحدها metadata |
| Open Redirect | 3xx إلى Host خارجي دون اتباعه | Confirmed |
| Host Header | External Location = Confirmed؛ body reflection = Potential | مختلط |
| HTML Injection | Element marker parsed داخل HTML | Confirmed |
| Reflected XSS | Executable parsed context، خارج textarea/template/style/title | Confirmed |
| SQL Injection | DB error جديد أو boolean differential مستقر | Confirmed |
| Path Traversal | Canary marker أو OS signature | Confirmed |
| File Upload | استرجاع marker بمحتوى قابل للتنفيذ | Confirmed |
| IDOR | Private marker من object غير مصرح | Confirmed؛ التشابه فقط Potential |
| Known Weak Credential | نجاح Credential اختبار واحدة مع success marker | Confirmed |
| Login Abuse | عدد محدود من المحاولات دون block | Potential |
| Generic Rate Limit | عدد محدود من الطلبات دون throttling | Potential |
| Stored XSS | تخزين وإعادة marker executable غير مشفر | Confirmed |
| SSRF | OAST callback فريد يصل من الخادم | Confirmed |
| Blind XSS | Script callback فريد بعد التخزين | Confirmed |

## قواعد مشتركة

- لا تستخدم قيم افتراضية وهمية للمدخلات الحساسة.
- المدخل الناقص يعيد `inconclusive`.
- كل وحدة تعيد `evidence` و`confidence` و`recommendation`.
- الإلغاء والميزانية يعاد رفعهما إلى المحرك ولا يتحولان إلى Finding.
- الفحص المغير للحالة لا يعمل افتراضيًا في الوحدات الحديثة.
