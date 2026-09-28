# ui/auth_dialog.py
import qtawesome as qta
from PySide6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QStackedWidget, QMessageBox, QFrame, QGraphicsDropShadowEffect
)
from PySide6.QtCore import Qt, QTimer, QPoint, Signal as pyqtSignal
from PySide6.QtGui import QFont, QColor, QAction

from config import APP_NAME, APP_VERSION, DEV_MODE, SHOW_OTP_ON_EMAIL_FAILURE, get_colors
from core.auth_db import auth_db
from core.email_service import generate_6char_otp, send_emailjs_otp

class AuthDialog(QDialog):
    """Enterprise Custom Frameless Authentication Dialog"""
    authenticated_signal = pyqtSignal(dict)  # Emitted when user logs in or completes registration
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} - Enterprise Authentication")
        self.resize(500, 640)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        
        self._drag_pos = QPoint()
        self.pending_email = ""
        self.pending_user = None
        self.pwd_visible_login = False
        self.pwd_visible_reg = False
        
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {c['bg']};
                color: {c['text']};
                border: 2px solid {c['border']};
                border-radius: 12px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
            QFrame#AuthCard {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 10px;
                padding: 20px;
            }}
            QLabel#BrandTitle {{
                font-size: 20px;
                font-weight: bold;
                color: {c['accent']};
                letter-spacing: 1px;
            }}
            QLabel#BrandSubTitle {{
                font-size: 11px;
                color: {c['text_sub']};
            }}
            QLabel#FormHeader {{
                font-size: 16px;
                font-weight: bold;
                color: {c['text']};
            }}
            QLabel#FormSubHeader {{
                font-size: 11px;
                color: {c['text_sub']};
            }}
            QLineEdit {{
                background-color: {c['bg']};
                color: {c['text']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 10px 12px;
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border: 1px solid {c['accent']};
            }}
            QPushButton#PrimaryBtn {{
                background-color: {c['accent']};
                color: #000000;
                font-weight: bold;
                font-size: 13px;
                border: none;
                border-radius: 6px;
                padding: 11px;
            }}
            QPushButton#PrimaryBtn:hover {{
                background-color: {c['accent_hover']};
            }}
            QPushButton#LinkBtn {{
                background-color: transparent;
                color: {c['accent']};
                border: none;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton#LinkBtn:hover {{
                text-decoration: underline;
            }}
        """)
        
        # 1. Custom Frameless Titlebar Header
        hdr_frame = QFrame()
        hdr_frame.setObjectName("DialogHeader")
        hdr_frame.setStyleSheet(f"""
            QFrame#DialogHeader {{
                background-color: {c['panel']};
                border-bottom: 1px solid {c['border']};
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                padding: 4px 10px;
            }}
            QLabel#DialogTitle {{
                font-size: 12px;
                font-weight: bold;
                color: {c['accent']};
            }}
            QPushButton#DialogCloseBtn {{
                background-color: transparent;
                color: {c['text_sub']};
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton#DialogCloseBtn:hover {{
                background-color: {c['danger']};
                color: white;
            }}
        """)
        
        lbl_hdr_title = QLabel(f" {APP_NAME} - Authentication")
        lbl_hdr_title.setObjectName("DialogTitle")
        
        btn_close = QPushButton()
        btn_close.setObjectName("DialogCloseBtn")
        btn_close.setIcon(qta.icon('fa5s.times', color='white'))
        btn_close.clicked.connect(self.reject)
        
        hdr_lay = QHBoxLayout()
        hdr_lay.setContentsMargins(6, 4, 6, 4)
        hdr_lay.addWidget(lbl_hdr_title)
        hdr_lay.addStretch()
        hdr_lay.addWidget(btn_close)
        hdr_frame.setLayout(hdr_lay)

        # 2. Stacked Authentication Views
        self.pages = QStackedWidget(self)
        self.pages.addWidget(self._build_login_page())      # 0
        self.pages.addWidget(self.self_build_signup_page()) # 1
        self.pages.addWidget(self._build_otp_page())        # 2
        self.pages.addWidget(self._build_reset_page())      # 3
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(hdr_frame)
        main_layout.addWidget(self.pages, stretch=1)
        self.setLayout(main_layout)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and hasattr(self, '_drag_pos'):
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    # ---------- 1. SIGN IN / LOGIN PAGE ----------
    def _build_login_page(self):
        c = get_colors()
        card = QFrame()
        card.setObjectName("AuthCard")
        
        # Branding Header
        lbl_brand = QLabel(APP_NAME.upper())
        lbl_brand.setObjectName("BrandTitle")
        
        lbl_brand_sub = QLabel("Security Operations & Threat Intelligence Center")
        lbl_brand_sub.setObjectName("BrandSubTitle")
        
        lbl_title = QLabel("Sign In")
        lbl_title.setObjectName("FormHeader")
        
        self.login_email = QLineEdit()
        self.login_email.setPlaceholderText("Email Address")
        self.login_email.addAction(qta.icon('fa5s.envelope', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        self.login_pwd = QLineEdit()
        self.login_pwd.setPlaceholderText("Password")
        self.login_pwd.setEchoMode(QLineEdit.Password)
        self.login_pwd.addAction(qta.icon('fa5s.lock', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        # Toggle Password Visibility Action
        self.act_pwd_toggle = QAction(qta.icon('fa5s.eye', color=c['text_sub']), "", self)
        self.act_pwd_toggle.triggered.connect(self._toggle_login_pwd_visibility)
        self.login_pwd.addAction(self.act_pwd_toggle, QLineEdit.TrailingPosition)
        
        btn_signin = QPushButton(" Sign In")
        btn_signin.setObjectName("PrimaryBtn")
        btn_signin.setIcon(qta.icon('fa5s.sign-in-alt', color='black'))
        btn_signin.clicked.connect(self._handle_login)
        
        btn_forgot = QPushButton("Forgot Password?")
        btn_forgot.setObjectName("LinkBtn")
        btn_forgot.clicked.connect(lambda: self.pages.setCurrentIndex(3))
        
        btn_signup_link = QPushButton("Don't have an account? Create Account")
        btn_signup_link.setObjectName("LinkBtn")
        btn_signup_link.clicked.connect(lambda: self.pages.setCurrentIndex(1))
        
        vbox = QVBoxLayout()
        vbox.setSpacing(10)
        vbox.addWidget(lbl_brand, alignment=Qt.AlignCenter)
        vbox.addWidget(lbl_brand_sub, alignment=Qt.AlignCenter)
        vbox.addSpacing(10)
        vbox.addWidget(lbl_title)
        vbox.addSpacing(4)
        vbox.addWidget(QLabel("Email Address:"))
        vbox.addWidget(self.login_email)
        vbox.addWidget(QLabel("Password:"))
        vbox.addWidget(self.login_pwd)
        vbox.addWidget(btn_forgot, alignment=Qt.AlignRight)
        vbox.addSpacing(8)
        vbox.addWidget(btn_signin)
        vbox.addSpacing(8)
        vbox.addWidget(btn_signup_link, alignment=Qt.AlignCenter)
        vbox.addStretch()
        
        card.setLayout(vbox)
        return card

    # ---------- 2. SIGN UP / REGISTRATION PAGE ----------
    def self_build_signup_page(self):
        c = get_colors()
        card = QFrame()
        card.setObjectName("AuthCard")
        
        lbl_title = QLabel("Create Account")
        lbl_title.setObjectName("FormHeader")
        
        lbl_sub = QLabel("Register an administrator account with 6-char email verification.")
        lbl_sub.setObjectName("FormSubHeader")
        
        self.reg_name = QLineEdit()
        self.reg_name.setPlaceholderText("Full Name")
        self.reg_name.addAction(qta.icon('fa5s.user', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        self.reg_email = QLineEdit()
        self.reg_email.setPlaceholderText("Email Address")
        self.reg_email.addAction(qta.icon('fa5s.envelope', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        self.reg_pwd = QLineEdit()
        self.reg_pwd.setPlaceholderText("Password")
        self.reg_pwd.setEchoMode(QLineEdit.Password)
        self.reg_pwd.addAction(qta.icon('fa5s.lock', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        self.reg_pwd_confirm = QLineEdit()
        self.reg_pwd_confirm.setPlaceholderText("Confirm Password")
        self.reg_pwd_confirm.setEchoMode(QLineEdit.Password)
        self.reg_pwd_confirm.addAction(qta.icon('fa5s.lock', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        btn_signup = QPushButton(" Register & Send Verification Code")
        btn_signup.setObjectName("PrimaryBtn")
        btn_signup.setIcon(qta.icon('fa5s.paper-plane', color='black'))
        btn_signup.clicked.connect(self._handle_signup)
        
        btn_login_link = QPushButton("Already registered? Sign In")
        btn_login_link.setObjectName("LinkBtn")
        btn_login_link.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        
        vbox = QVBoxLayout()
        vbox.setSpacing(8)
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_sub)
        vbox.addSpacing(6)
        vbox.addWidget(QLabel("Full Name:"))
        vbox.addWidget(self.reg_name)
        vbox.addWidget(QLabel("Email Address:"))
        vbox.addWidget(self.reg_email)
        vbox.addWidget(QLabel("Password:"))
        vbox.addWidget(self.reg_pwd)
        vbox.addWidget(QLabel("Confirm Password:"))
        vbox.addWidget(self.reg_pwd_confirm)
        vbox.addSpacing(10)
        vbox.addWidget(btn_signup)
        vbox.addWidget(btn_login_link, alignment=Qt.AlignCenter)
        vbox.addStretch()
        
        card.setLayout(vbox)
        return card

    # ---------- 3. 6-CHARACTER OTP VERIFICATION MODAL ----------
    def _build_otp_page(self):
        c = get_colors()
        card = QFrame()
        card.setObjectName("AuthCard")
        
        lbl_title = QLabel("Email Verification")
        lbl_title.setObjectName("FormHeader")
        
        self.lbl_otp_sub = QLabel("A 6-character code was dispatched via EmailJS to your email address.")
        self.lbl_otp_sub.setObjectName("FormSubHeader")
        self.lbl_otp_sub.setWordWrap(True)
        
        self.input_otp = QLineEdit()
        self.input_otp.setPlaceholderText("A 8 K 9 M 2")
        self.input_otp.setMaxLength(6)
        self.input_otp.setAlignment(Qt.AlignCenter)
        self.input_otp.setFont(QFont("Consolas", 20, QFont.Bold))
        self.input_otp.setStyleSheet(f"""
            QLineEdit {{
                letter-spacing: 14px;
                color: {c['success']};
                border: 2px solid {c['accent']};
                padding: 12px;
                background-color: #080d14;
            }}
        """)
        
        btn_verify = QPushButton(" Verify Code & Activate Account")
        btn_verify.setObjectName("PrimaryBtn")
        btn_verify.setIcon(qta.icon('fa5s.check-circle', color='black'))
        btn_verify.clicked.connect(self._handle_otp_verify)
        
        self.btn_resend_otp = QPushButton("Resend Verification Code")
        self.btn_resend_otp.setObjectName("LinkBtn")
        self.btn_resend_otp.clicked.connect(self._handle_resend_otp)
        
        vbox = QVBoxLayout()
        vbox.setSpacing(12)
        vbox.addWidget(lbl_title)
        vbox.addWidget(self.lbl_otp_sub)
        vbox.addSpacing(15)
        vbox.addWidget(QLabel("Enter 6-Character Verification Code:"))
        vbox.addWidget(self.input_otp)
        vbox.addSpacing(15)
        vbox.addWidget(btn_verify)
        vbox.addWidget(self.btn_resend_otp, alignment=Qt.AlignCenter)
        vbox.addStretch()
        
        card.setLayout(vbox)
        return card

    # ---------- 4. FORGOT PASSWORD & RESET PAGE ----------
    def _build_reset_page(self):
        c = get_colors()
        card = QFrame()
        card.setObjectName("AuthCard")
        
        lbl_title = QLabel("Password Recovery")
        lbl_title.setObjectName("FormHeader")
        
        lbl_sub = QLabel("Request a 6-character reset code to update your password.")
        lbl_sub.setObjectName("FormSubHeader")
        
        self.reset_email = QLineEdit()
        self.reset_email.setPlaceholderText("Registered Email Address")
        self.reset_email.addAction(qta.icon('fa5s.envelope', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        self.reset_otp = QLineEdit()
        self.reset_otp.setPlaceholderText("6-Char Reset Code (e.g. X9B2K7)")
        self.reset_otp.setMaxLength(6)
        self.reset_otp.setVisible(False)
        self.reset_otp.setAlignment(Qt.AlignCenter)
        self.reset_otp.setFont(QFont("Consolas", 14, QFont.Bold))
        
        self.reset_new_pwd = QLineEdit()
        self.reset_new_pwd.setPlaceholderText("New Password")
        self.reset_new_pwd.setEchoMode(QLineEdit.Password)
        self.reset_new_pwd.setVisible(False)
        self.reset_new_pwd.addAction(qta.icon('fa5s.lock', color=c['text_sub']), QLineEdit.LeadingPosition)
        
        self.btn_send_reset = QPushButton(" Send Reset Code via Email")
        self.btn_send_reset.setObjectName("PrimaryBtn")
        self.btn_send_reset.setIcon(qta.icon('fa5s.paper-plane', color='black'))
        self.btn_send_reset.clicked.connect(self._handle_send_reset_otp)
        
        self.btn_confirm_reset = QPushButton(" Set New Password")
        self.btn_confirm_reset.setObjectName("PrimaryBtn")
        self.btn_confirm_reset.setIcon(qta.icon('fa5s.key', color='black'))
        self.btn_confirm_reset.setVisible(False)
        self.btn_confirm_reset.clicked.connect(self._handle_confirm_reset)
        
        btn_back_login = QPushButton("Back to Sign In")
        btn_back_login.setObjectName("LinkBtn")
        btn_back_login.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        
        vbox = QVBoxLayout()
        vbox.setSpacing(10)
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_sub)
        vbox.addSpacing(10)
        vbox.addWidget(QLabel("Email Address:"))
        vbox.addWidget(self.reset_email)
        vbox.addWidget(self.reset_otp)
        vbox.addWidget(self.reset_new_pwd)
        vbox.addSpacing(10)
        vbox.addWidget(self.btn_send_reset)
        vbox.addWidget(self.btn_confirm_reset)
        vbox.addWidget(btn_back_login, alignment=Qt.AlignCenter)
        vbox.addStretch()
        
        card.setLayout(vbox)
        return card

    # ---------- EVENT HANDLERS & LOGIC ----------
    def _toggle_login_pwd_visibility(self):
        c = get_colors()
        self.pwd_visible_login = not self.pwd_visible_login
        if self.pwd_visible_login:
            self.login_pwd.setEchoMode(QLineEdit.Normal)
            self.act_pwd_toggle.setIcon(qta.icon('fa5s.eye-slash', color=c['accent']))
        else:
            self.login_pwd.setEchoMode(QLineEdit.Password)
            self.act_pwd_toggle.setIcon(qta.icon('fa5s.eye', color=c['text_sub']))

    def _handle_login(self):
        email = self.login_email.text().strip()
        pwd = self.login_pwd.text()
        if not email or not pwd:
            QMessageBox.warning(self, "Auth Error", "Please fill in both email and password fields.")
            return
            
        success, msg, user = auth_db.authenticate_user(email, pwd)
        if success:
            auth_db.create_session(user["id"])
            self.authenticated_signal.emit(user)
            self.accept()
        else:
            if "not verified" in msg:
                self.pending_email = email
                self.pending_user = user
                self._send_and_show_otp(email, user.get("name", "User"))
            else:
                QMessageBox.critical(self, "Login Failed", msg)

    def _handle_signup(self):
        name = self.reg_name.text().strip()
        email = self.reg_email.text().strip().lower()
        pwd = self.reg_pwd.text()
        confirm = self.reg_pwd_confirm.text()
        
        if not name or not email or not pwd:
            QMessageBox.warning(self, "Registration Error", "Please fill in all required registration fields.")
            return
            
        if pwd != confirm:
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match!")
            return
        if len(pwd) < 12:
            QMessageBox.warning(self, "Weak Password", "Password must contain at least 12 characters.")
            return
            
        user_id = auth_db.register_user(name, email, pwd)
        if not user_id:
            QMessageBox.critical(self, "Registration Failed", "Email address is already registered!")
            return
            
        self.pending_email = email
        self.pending_user = {"id": user_id, "name": name, "email": email, "role": "Administrator"}
        if not self._send_and_show_otp(email, name, purpose="registration"):
            auth_db.delete_unverified_user(user_id)

    def _send_and_show_otp(self, email, user_name, purpose="verification"):
        otp_code = generate_6char_otp()
        ok, res_msg = send_emailjs_otp(email, user_name, otp_code, purpose=purpose)
        if ok or (DEV_MODE and SHOW_OTP_ON_EMAIL_FAILURE):
            auth_db.store_otp(email, otp_code, expires_in_minutes=10)
        self.input_otp.clear()
        self.pages.setCurrentIndex(2)
        if ok:
            self.lbl_otp_sub.setText(f"A 6-character code was dispatched via EmailJS to <b>{email}</b>.")
            QMessageBox.information(self, "Code Sent", f"6-Character Verification Code sent to {email}!")
        else:
            if DEV_MODE and SHOW_OTP_ON_EMAIL_FAILURE:
                self.lbl_otp_sub.setText(f"Development OTP: <b>{otp_code}</b>")
                QMessageBox.warning(self, "Development Only", "Email service unavailable; development OTP is shown.")
            else:
                self.lbl_otp_sub.setText("Unable to send the verification code. Please try again later.")
                QMessageBox.warning(self, "Verification Unavailable", "The verification email could not be sent. No code was displayed.")
        return ok

    def _handle_otp_verify(self):
        code = self.input_otp.text().strip()
        if len(code) != 6:
            QMessageBox.warning(self, "OTP Error", "Verification code must be exactly 6 characters.")
            return
            
        if auth_db.verify_otp(self.pending_email, code):
            auth_db.mark_email_verified(self.pending_email)
            user = auth_db.get_user_by_email(self.pending_email)
            if user:
                auth_db.create_session(user["id"])
                self.authenticated_signal.emit(user)
            QMessageBox.information(self, "Account Verified", "Email address verified successfully!")
            self.accept()
        else:
            QMessageBox.critical(self, "Verification Failed", "Invalid or expired 6-character verification code.")

    def _handle_resend_otp(self):
        if self.pending_email and self.pending_user:
            self._send_and_show_otp(self.pending_email, self.pending_user.get("name", "User"), purpose="registration")

    def _handle_send_reset_otp(self):
        email = self.reset_email.text().strip().lower()
        user = auth_db.get_user_by_email(email)
        if not user:
            QMessageBox.information(self, "Recovery Request", "If the account exists, recovery instructions will be sent.")
            return
            
        self.pending_email = email
        otp_code = generate_6char_otp()
        ok, res_msg = send_emailjs_otp(email, user.get("name", "User"), otp_code, purpose="password_reset")
        if ok or (DEV_MODE and SHOW_OTP_ON_EMAIL_FAILURE):
            auth_db.store_otp(email, otp_code, expires_in_minutes=10)
        
        self.reset_otp.setVisible(True)
        self.reset_new_pwd.setVisible(True)
        self.btn_send_reset.setVisible(False)
        self.btn_confirm_reset.setVisible(True)
        
        if ok:
            QMessageBox.information(self, "Reset Code Sent", "A recovery code was sent to the registered email address.")
        else:
            if DEV_MODE and SHOW_OTP_ON_EMAIL_FAILURE:
                QMessageBox.warning(self, "Development Only", "Email service unavailable; development OTP is shown.")
            else:
                self.reset_otp.clear()
                self.reset_otp.setVisible(False)
                self.reset_new_pwd.clear()
                self.reset_new_pwd.setVisible(False)
                self.btn_send_reset.setVisible(True)
                self.btn_confirm_reset.setVisible(False)
                QMessageBox.warning(self, "Recovery Unavailable", "The recovery email could not be sent. No code was displayed.")

    def _handle_confirm_reset(self):
        code = self.reset_otp.text().strip()
        new_pwd = self.reset_new_pwd.text()
        
        if not code or not new_pwd:
            QMessageBox.warning(self, "Reset Error", "Please fill in the 6-char OTP code and new password.")
            return
        if len(new_pwd) < 12:
            QMessageBox.warning(self, "Reset Error", "New password must contain at least 12 characters.")
            return
            
        if auth_db.verify_otp(self.pending_email, code):
            if not auth_db.update_password(self.pending_email, new_pwd):
                QMessageBox.critical(self, "Reset Failed", "Unable to update the password.")
                return
            QMessageBox.information(self, "Password Reset", "Password updated successfully! Please sign in.")
            self.pages.setCurrentIndex(0)
        else:
            QMessageBox.critical(self, "Reset Failed", "Invalid or expired OTP verification code.")
