# دليل التشغيل الإنتاجي الآمن

## 1. المتطلبات

- Python 3.11 أو أحدث.
- صلاحيات التقاط الشبكة فقط عند الحاجة، ويفضل تشغيل Collector بصلاحيات محدودة بدل تشغيل الواجهة كـ root.
- حساب EmailJS مخصص للإرسال، مع Service ID وTemplate ID وPublic Key وPrivate Key.
- لا تضع المفاتيح داخل الكود أو ملف ZIP أو Git.

## 2. إعداد EmailJS

انسخ ملف البيئة:

```bash
cp .env.example .env
chmod 600 .env
```

ضع القيم في `.env` أو Secret Manager:

```env
NETSEC_EMAILJS_SERVICE_ID=your-service-id
NETSEC_EMAILJS_TEMPLATE_ID=your-template-id
NETSEC_EMAILJS_PUBLIC_KEY=your-public-key
NETSEC_EMAILJS_PRIVATE_KEY=your-private-key
NETSEC_DEV_MODE=false
NETSEC_SHOW_OTP_ON_EMAIL_FAILURE=false
NETSEC_SESSION_TTL_SECONDS=28800
NETSEC_LOG_LEVEL=INFO
```

في الإنتاج يجب أن تبقى القيمتان التاليتان `false`:

```env
NETSEC_DEV_MODE=false
NETSEC_SHOW_OTP_ON_EMAIL_FAILURE=false
```

إذا غابت أي قيمة من قيم EmailJS، يتوقف إرسال OTP برسالة آمنة ولا يظهر الرمز للمستخدم ولا يُسجل في السجلات.

## 3. تدوير المفاتيح القديمة

بما أن الإصدار السابق احتوى قيمًا حساسة داخل المصدر، يجب إلغاء/تدوير المفاتيح القديمة من لوحة EmailJS قبل التشغيل، حتى لو لم تعد موجودة في الإصدار الجديد.

## 4. التشغيل

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

للتوزيع على أجهزة مستخدمين، الأفضل نقل إرسال البريد إلى Backend مخصص وعدم وضع EmailJS Private Key على جهاز العميل. الواجهة تتصل بالـ Backend عبر HTTPS، والـ Backend وحده يتعامل مع EmailJS.

## 5. اختبار قبل الإنتاج

```bash
QT_QPA_PLATFORM=offscreen pytest -q
python -m py_compile $(find . -name '*.py' -print)
```

يجب ألا توجد الملفات التالية داخل الإصدار:

- `data/netsec.db`
- `data/netsec.db-wal`
- `data/netsec.db-shm`
- `.env`
- `__pycache__`
- ملفات OTP أو exports اختبارية

## 6. سلوك الجلسات

عند تغيير أو إعادة تعيين كلمة المرور:

- يتم تحديث hash وكلمة المرور داخل transaction.
- يتم إلغاء جميع جلسات المستخدم نفسه.
- لا يتم تسجيل خروج المستخدمين الآخرين.
- يجب تسجيل الدخول مجددًا أو إنشاء جلسة جديدة بعد النجاح.

## 7. ضوابط التشغيل

- استخدم حساب EmailJS محدود الغرض.
- لا تسجل payload أو OTP أو Private Key في logs.
- راقب فشل الإرسال ومعدلات OTP دون تسجيل الرمز.
- احتفظ بنسخ احتياطية مشفرة لبيانات التطبيق فقط.
- لا تضمّن بيانات المستخدمين أو قاعدة SQLite في artifacts.
