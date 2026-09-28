# main.py
import sys
import ctypes
import os
from PySide6.QtWidgets import QApplication, QMessageBox, QDialog
from config import APP_NAME, get_app_stylesheet
from core.auth_db import auth_db
from ui.auth_dialog import AuthDialog
from ui.main_window import MainWindow

def is_admin():
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    
    # Check for Admin Privileges
    if not is_admin():
        QMessageBox.warning(
            None,
            "Administrator Rights Recommended",
            "⚠️ The application is not running with Administrator privileges.\n\n"
            "Live packet sniffing and ARP scanning may require elevated rights to access network adapters.\n\n"
            "For full features, please restart using 'Run as Administrator'."
        )
    
    # Apply Default Theme Stylesheet
    app.setStyleSheet(get_app_stylesheet("Cyberpunk"))
    
    # Check if a valid login session exists in database
    session_user = auth_db.get_current_user_session()
    if not session_user:
        auth_dialog = AuthDialog()
        if auth_dialog.exec_() != QDialog.Accepted:
            sys.exit(0)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
