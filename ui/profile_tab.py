# ui/profile_tab.py
import qtawesome as qta
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QGridLayout, QMessageBox
)
from PySide6.QtCore import Qt, Signal as pyqtSignal
from PySide6.QtGui import QFont, QColor

from config import get_colors
from core.auth_db import auth_db

class ProfileTab(QWidget):
    """User Profile & Account Security Management Tab"""
    logout_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_user = None
        self._setup_ui()
        self.load_user_profile()
    
    def _setup_ui(self):
        c = get_colors()
        # 1. User Header Card
        self.card_header = QFrame()
        self.card_header.setObjectName("ProfileHeaderCard")
        self.card_header.setStyleSheet(f"""
            QFrame#ProfileHeaderCard {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 10px;
                padding: 15px;
            }}
            QFrame#ProfileHeaderCard QLabel {{
                border: none;
                background: transparent;
                padding: 0px;
            }}
            QLabel#UserTitle {{
                font-size: 20px;
                font-weight: bold;
                color: {c['text']};
            }}
            QLabel#UserRole {{
                font-size: 13px;
                color: {c['accent']};
                font-weight: bold;
            }}
            QLabel#UserStatus {{
                font-size: 12px;
                color: {c['success']};
                font-weight: bold;
            }}
        """)
        
        self.lbl_avatar = QLabel()
        self.lbl_avatar.setPixmap(qta.icon('fa5s.user-shield', color=c['accent']).pixmap(64, 64))
        
        self.lbl_name = QLabel("Administrator")
        self.lbl_name.setObjectName("UserTitle")
        
        self.lbl_email = QLabel("admin@company.com")
        self.lbl_email.setStyleSheet(f"color: {c['text_sub']}; font-size: 13px;")
        
        self.lbl_role = QLabel("Role: System Administrator")
        self.lbl_role.setObjectName("UserRole")
        
        self.lbl_status = QLabel("Security Status: Verified Account (EmailJS Verified)")
        self.lbl_status.setObjectName("UserStatus")
        
        vbox_info = QVBoxLayout()
        vbox_info.setSpacing(6)
        vbox_info.addWidget(self.lbl_name)
        vbox_info.addWidget(self.lbl_email)
        vbox_info.addWidget(self.lbl_role)
        vbox_info.addWidget(self.lbl_status)
        
        hdr_layout = QHBoxLayout()
        hdr_layout.setContentsMargins(10, 10, 10, 10)
        hdr_layout.addWidget(self.lbl_avatar)
        hdr_layout.addSpacing(15)
        hdr_layout.addLayout(vbox_info, stretch=1)
        self.card_header.setLayout(hdr_layout)

        # 2. Account Details Grid Card
        card_details = QFrame()
        card_details.setObjectName("ProfileDetailsCard")
        card_details.setStyleSheet(f"""
            QFrame#ProfileDetailsCard {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 10px;
                padding: 15px;
            }}
            QFrame#ProfileDetailsCard QLabel {{
                border: none;
                background: transparent;
                font-size: 13px;
                color: {c['text']};
            }}
            QLineEdit {{
                background-color: {c['bg']};
                color: {c['text']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        
        grid = QGridLayout()
        grid.setSpacing(12)
        
        grid.addWidget(QLabel("<b>Full Name:</b>"), 0, 0)
        self.input_name = QLineEdit()
        grid.addWidget(self.input_name, 0, 1)
        
        grid.addWidget(QLabel("<b>Email Address:</b>"), 1, 0)
        self.input_email = QLineEdit()
        self.input_email.setReadOnly(True)
        grid.addWidget(self.input_email, 1, 1)
        
        grid.addWidget(QLabel("<b>Account Role:</b>"), 2, 0)
        self.lbl_role_val = QLabel("System Administrator")
        grid.addWidget(self.lbl_role_val, 2, 1)
        
        grid.addWidget(QLabel("<b>Registration Date:</b>"), 3, 0)
        self.lbl_created_val = QLabel("N/A")
        grid.addWidget(self.lbl_created_val, 3, 1)

        self.btn_save_profile = QPushButton(" Save Profile Name")
        self.btn_save_profile.setIcon(qta.icon('fa5s.save', color='black'))
        self.btn_save_profile.setStyleSheet(f"background-color: {c['accent']}; color: black; font-weight: bold; padding: 9px; border-radius: 6px;")
        self.btn_save_profile.clicked.connect(self._save_profile)
        grid.addWidget(self.btn_save_profile, 4, 1, alignment=Qt.AlignRight)
        
        card_details.setLayout(grid)

        # 3. Password Change Card
        card_pwd = QFrame()
        card_pwd.setObjectName("ProfilePwdCard")
        card_pwd.setStyleSheet(f"""
            QFrame#ProfilePwdCard {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 10px;
                padding: 15px;
            }}
            QFrame#ProfilePwdCard QLabel {{
                border: none;
                background: transparent;
                font-size: 13px;
                color: {c['text']};
            }}
            QLineEdit {{
                background-color: {c['bg']};
                color: {c['text']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        
        pwd_vbox = QVBoxLayout()
        pwd_vbox.setSpacing(10)
        
        pwd_vbox.addWidget(QLabel("<b>Security & Password Settings:</b>"))
        
        self.input_curr_pwd = QLineEdit()
        self.input_curr_pwd.setPlaceholderText("Current Password")
        self.input_curr_pwd.setEchoMode(QLineEdit.Password)
        
        self.input_new_pwd = QLineEdit()
        self.input_new_pwd.setPlaceholderText("New Password")
        self.input_new_pwd.setEchoMode(QLineEdit.Password)
        
        self.input_confirm_pwd = QLineEdit()
        self.input_confirm_pwd.setPlaceholderText("Confirm New Password")
        self.input_confirm_pwd.setEchoMode(QLineEdit.Password)
        
        btn_update_pwd = QPushButton(" Change Password")
        btn_update_pwd.setIcon(qta.icon('fa5s.key', color='black'))
        btn_update_pwd.setStyleSheet(f"background-color: {c['accent']}; color: black; font-weight: bold; padding: 10px; border-radius: 6px;")
        btn_update_pwd.clicked.connect(self._change_password)
        
        pwd_vbox.addWidget(self.input_curr_pwd)
        pwd_vbox.addWidget(self.input_new_pwd)
        pwd_vbox.addWidget(self.input_confirm_pwd)
        pwd_vbox.addWidget(btn_update_pwd, alignment=Qt.AlignRight)
        
        card_pwd.setLayout(pwd_vbox)

        # 4. Logout Action
        btn_logout = QPushButton(" Sign Out / Logout")
        btn_logout.setIcon(qta.icon('fa5s.sign-out-alt', color='white'))
        btn_logout.setStyleSheet(f"background-color: {c['danger']}; color: white; font-weight: bold; font-size: 13px; padding: 12px; border-radius: 6px;")
        btn_logout.clicked.connect(self._handle_logout)

        root = QVBoxLayout()
        root.setContentsMargins(15, 15, 15, 15)
        root.setSpacing(15)
        root.addWidget(self.card_header)
        root.addWidget(card_details)
        root.addWidget(card_pwd)
        root.addStretch()
        root.addWidget(btn_logout, alignment=Qt.AlignRight)
        self.setLayout(root)

    def load_user_profile(self):
        user = auth_db.get_current_user_session()
        if not user:
            self.current_user = None
            self.lbl_name.setText("No active session")
            self.lbl_email.setText("")
            self.lbl_role.setText("Role: —")
            self.lbl_status.setText("Security Status: Session expired")
            self.input_name.clear()
            self.input_email.clear()
            self.lbl_role_val.setText("—")
            self.lbl_created_val.setText("—")
            return
        self.current_user = user
        
        self.lbl_name.setText(user.get("name", "User"))
        self.lbl_email.setText(user.get("email", "admin@company.com"))
        self.lbl_role.setText(f"Role: {user.get('role', 'Administrator')}")
        
        if user.get("is_verified"):
            self.lbl_status.setText("Security Status: Verified Account (EmailJS Verified)")
        else:
            self.lbl_status.setText("Security Status: Unverified Account")
            
        self.input_name.setText(user.get("name", ""))
        self.input_email.setText(user.get("email", ""))
        self.lbl_role_val.setText(user.get("role", "Administrator"))
        self.lbl_created_val.setText(user.get("created_at", "N/A"))

    def _change_password(self):
        curr_pwd = self.input_curr_pwd.text()
        new_pwd = self.input_new_pwd.text()
        confirm = self.input_confirm_pwd.text()
        
        if not curr_pwd or not new_pwd or not confirm:
            QMessageBox.warning(self, "Error", "Please fill in all password fields.")
            return
            
        if new_pwd != confirm:
            QMessageBox.warning(self, "Mismatch", "New passwords do not match!")
            return
            
        email = self.current_user.get("email")
        if email:
            if not auth_db.change_password(email, curr_pwd, new_pwd):
                QMessageBox.critical(self, "Password Error", "Current password is incorrect or the new password is too short.")
                return
            self.input_curr_pwd.clear()
            self.input_new_pwd.clear()
            self.input_confirm_pwd.clear()
            QMessageBox.information(self, "Success", "Password updated successfully!")

    def _save_profile(self):
        if not self.current_user:
            return
        name = self.input_name.text().strip()
        if not auth_db.update_profile_name(self.current_user.get("id"), name):
            QMessageBox.warning(self, "Profile Error", "Name must contain between 2 and 120 characters.")
            return
        self.load_user_profile()
        QMessageBox.information(self, "Profile Updated", "Your profile name was updated successfully.")

    def _handle_logout(self):
        res = QMessageBox.question(self, "Confirm Logout", "Are you sure you want to sign out?",
                                   QMessageBox.Yes | QMessageBox.No)
        if res == QMessageBox.Yes:
            auth_db.clear_session()
            self.logout_requested.emit()
