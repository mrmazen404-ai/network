# ui/toast_notification.py
import qtawesome as qta
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QGraphicsOpacityEffect)
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, Signal as pyqtSignal
from config import get_colors

class ToastNotification(QFrame):
    action_clicked = pyqtSignal(dict)
    
    def __init__(self, title, message, category="info", data=None, parent=None, duration_ms=5000):
        super().__init__(parent)
        self.title_str = title
        self.message_str = message
        self.category = category
        self.data = data or {}
        self.duration_ms = duration_ms
        
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.SubWindow)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        self._setup_ui()
        self._setup_animation()

    def _setup_ui(self):
        c = get_colors()
        
        accent_color = {
            "success": c['success'],
            "danger":  c['danger'],
            "warning": c['warning'],
            "info":    c['accent']
        }.get(self.category, c['accent'])
        
        icon_name = {
            "success": "fa5s.check-circle",
            "danger":  "fa5s.exclamation-triangle",
            "warning": "fa5s.exclamation-circle",
            "info":    "fa5s.info-circle"
        }.get(self.category, "fa5s.info-circle")

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-left: 5px solid {accent_color};
                border-radius: 8px;
                padding: 8px;
            }}
            QLabel#ToastTitle {{
                color: {c['text']};
                font-weight: bold;
                font-size: 13px;
            }}
            QLabel#ToastMessage {{
                color: {c['text_sub']};
                font-size: 11px;
            }}
            QPushButton#ActionBtn {{
                background-color: {accent_color};
                color: white;
                border: none;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton#CloseBtn {{
                background-color: transparent;
                color: {c['text_sub']};
                border: none;
                font-size: 14px;
                font-weight: bold;
            }}
            QPushButton#CloseBtn:hover {{
                color: {c['text']};
            }}
        """)

        layout = QHBoxLayout()
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        # Icon Label
        lbl_icon = QLabel()
        lbl_icon.setPixmap(qta.icon(icon_name, color=accent_color).pixmap(24, 24))
        layout.addWidget(lbl_icon)

        # Text Content
        vbox = QVBoxLayout()
        vbox.setSpacing(2)
        
        lbl_title = QLabel(self.title_str)
        lbl_title.setObjectName("ToastTitle")
        
        lbl_msg = QLabel(self.message_str)
        lbl_msg.setObjectName("ToastMessage")
        lbl_msg.setWordWrap(True)
        
        vbox.addWidget(lbl_title)
        vbox.addWidget(lbl_msg)
        layout.addLayout(vbox, stretch=1)

        # Action Button (Optional)
        if self.category == "success" and "mac" in self.data:
            btn_action = QPushButton("Trust Device")
            btn_action.setObjectName("ActionBtn")
            btn_action.clicked.connect(self._on_action)
            layout.addWidget(btn_action)

        # Close Button
        btn_close = QPushButton("✕")
        btn_close.setObjectName("CloseBtn")
        btn_close.clicked.connect(self.close_toast)
        layout.addWidget(btn_close)

        self.setLayout(layout)
        self.setFixedWidth(380)

    def _setup_animation(self):
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        
        # Fade In
        self.anim_in = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim_in.setDuration(300)
        self.anim_in.setStartValue(0.0)
        self.anim_in.setEndValue(1.0)
        self.anim_in.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim_in.start()

        # Auto Dismiss Timer
        self.dismiss_timer = QTimer(self)
        self.dismiss_timer.setSingleShot(True)
        self.dismiss_timer.setInterval(self.duration_ms)
        self.dismiss_timer.timeout.connect(self.close_toast)
        self.dismiss_timer.start()

    def close_toast(self):
        if hasattr(self, 'anim_out'):
            return
            
        self.anim_out = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.anim_out.setDuration(300)
        self.anim_out.setStartValue(1.0)
        self.anim_out.setEndValue(0.0)
        self.anim_out.setEasingCurve(QEasingCurve.InOutQuad)
        self.anim_out.finished.connect(self.deleteLater)
        self.anim_out.start()

    def _on_action(self):
        self.action_clicked.emit(self.data)
        self.close_toast()

class ToastManager:
    """Manages floating stack positioning for active toast overlays"""
    def __init__(self, parent_window):
        self.parent_window = parent_window
        self.active_toasts = []

    def show_toast(self, title, message, category="info", data=None, duration_ms=5000):
        toast = ToastNotification(title, message, category=category, data=data, parent=self.parent_window, duration_ms=duration_ms)
        toast.destroyed.connect(lambda: self._remove_toast(toast))
        self.active_toasts.append(toast)
        self.reposition_toasts()
        toast.show()
        return toast

    def _remove_toast(self, toast):
        if toast in self.active_toasts:
            self.active_toasts.remove(toast)
            self.reposition_toasts()

    def reposition_toasts(self):
        if not self.parent_window:
            return
            
        parent_rect = self.parent_window.rect()
        margin_right = 20
        margin_bottom = 40
        spacing = 10
        
        current_y = parent_rect.height() - margin_bottom
        
        for toast in reversed(self.active_toasts):
            current_y -= toast.height()
            x = parent_rect.width() - toast.width() - margin_right
            toast.move(x, current_y)
            current_y -= spacing
