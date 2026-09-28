# ui/bottom_bar.py
import psutil
import qtawesome as qta
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel)
from PySide6.QtCore import Qt
from config import get_colors

class BottomBar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("BottomBar")
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QFrame#BottomBar {{
                background-color: {c['panel']};
                border-top: 1px solid {c['border']};
                padding: 4px 16px;
            }}
            QLabel {{
                color: {c['text_sub']};
                font-size: 11px;
            }}
            QLabel#ValueLbl {{
                color: {c['accent']};
                font-weight: bold;
            }}
        """)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(12, 4, 12, 4)
        
        self.lbl_down = QLabel("Download: 0.0 KB/s")
        self.lbl_up   = QLabel("Upload: 0.0 KB/s")
        self.lbl_cpu  = QLabel("CPU: 0%")
        self.lbl_ram  = QLabel("RAM: 0%")
        self.lbl_sniff= QLabel("Sniffer: Active")
        self.lbl_sniff.setObjectName("ValueLbl")
        
        layout.addWidget(self.lbl_down)
        layout.addSpacing(15)
        layout.addWidget(self.lbl_up)
        layout.addSpacing(25)
        layout.addWidget(self.lbl_cpu)
        layout.addSpacing(15)
        layout.addWidget(self.lbl_ram)
        layout.addStretch()
        layout.addWidget(self.lbl_sniff)
        
        self.setLayout(layout)
    
    def update_speed(self, down, up):
        self.lbl_down.setText(f"Down: {down:.1f} KB/s")
        self.lbl_up.setText(f"Up: {up:.1f} KB/s")
        
        try:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.lbl_cpu.setText(f"CPU: {cpu}%")
            self.lbl_ram.setText(f"RAM: {ram}%")
        except Exception:
            pass

    def set_sniff_status(self, is_running):
        if is_running:
            self.lbl_sniff.setText("Sniffer: Active")
        else:
            self.lbl_sniff.setText("Sniffer: Stopped")
