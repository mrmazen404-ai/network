# Network Security Monitor — الإصدار النهائي الموحد

هذه هي النسخة الموحدة من تطبيق Desktop. كل ما يخص الحسابات والتحقق موجود داخل نفس المشروع:

- إنشاء حساب.
- تسجيل الدخول.
- تحقق البريد عبر EmailJS.
- OTP من 6 حروف وأرقام.
- إعادة إرسال OTP.
- استعادة كلمة المرور.
- تغيير كلمة المرور.
- تبويب الملف الشخصي.
- تسجيل الخروج وإلغاء الجلسات.
- قالب EmailJS HTML/CSS.
- مخطط المعمارية وحالات الاستخدام.

## التشغيل

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
python main.py
```

## EmailJS

املأ الملف `.env` فقط:

```env
NETSEC_EMAILJS_SERVICE_ID=service_chrj4qd
NETSEC_EMAILJS_TEMPLATE_ID=template_pa4jzrw
NETSEC_EMAILJS_PUBLIC_KEY=ضع_المفتاح_العام
NETSEC_EMAILJS_PRIVATE_KEY=ضع_المفتاح_الخاص
NETSEC_DEV_MODE=false
NETSEC_SHOW_OTP_ON_EMAIL_FAILURE=false
```

لا تضع `.env` داخل Git أو ZIP. يجب أن يكون حقل To Email في قالب EmailJS:

```text
{{to_email}}
```

## قالب الرسالة

افتح `EMAILJS_TEMPLATE_HTML.html` وانسخ محتواه إلى قالب EmailJS `template_pa4jzrw`. المتغيرات المستخدمة:

```text
{{to_email}}
{{to_name}}
{{otp_code}}
{{purpose_label}}
{{expires_minutes}}
{{app_name}}
{{message}}
```

## الاختبار

```bash
QT_QPA_PLATFORM=offscreen pytest -q
python -m py_compile $(find . -name '*.py' -print)
```

## الملفات المهمة

- `ui/auth_dialog.py`: إنشاء الحساب، الدخول، OTP، الاستعادة.
- `core/email_service.py`: طلب EmailJS.
- `core/auth_db.py`: المستخدمون، OTP، الجلسات، كلمات المرور.
- `ui/profile_tab.py`: الملف الشخصي وتغيير كلمة المرور.
- `EMAILJS_TEMPLATE_HTML.html`: قالب الرسالة.
- `ACCOUNT_AUTH_EMAILJS_ARCHITECTURE_AR.md`: المخطط الكامل.

## تنبيه أمني

المفتاح الخاص لا يدخل الكود ولا الحزمة. بما أن مفتاحًا خاصًا تم مشاركته سابقًا في المحادثة، يجب تدويره من EmailJS بعد الإعداد ووضع المفتاح الجديد في `.env`.
