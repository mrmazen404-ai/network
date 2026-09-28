# ui/sidebar.py
import qtawesome as qta
from PySide6.QtWidgets import (QFrame, QVBoxLayout, QPushButton, QLabel)
from PySide6.QtCore import Signal as pyqtSignal, Qt
from config import get_colors

class Sidebar(QFrame):
    nav_changed = pyqtSignal(int)
    
    NAV_ITEMS = [
        ("Dashboard", 0, 'fa5s.chart-line'),
        ("Topology Map", 1, 'fa5s.sitemap'),
        ("LAN Devices", 2, 'fa5s.desktop'),
        ("Packet Sniffer", 3, 'fa5s.network-wired'),
        ("Port Scanner", 4, 'fa5s.search'),
        ("Threat Alerts", 5, 'fa5s.bell'),
        ("Shell Terminal", 6, 'fa5s.terminal'),
        ("Visual Analytics", 7, 'fa5s.chart-pie'),
        ("User Profile", 8, 'fa5s.user-shield'),
    ]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SidebarFrame")
        self.buttons = []
        self.active_index = 0
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QFrame#SidebarFrame {{
                background-color: {c['panel']};
                border-right: 2px solid {c['border']};
                min-width: 200px;
                max-width: 220px;
            }}
            QPushButton {{
                text-align: left;
                padding: 12px 16px;
                font-size: 13px;
                background-color: transparent;
                color: {c['text']};
                border: none;
                border-radius: 6px;
            }}
            QPushButton:hover {{
                background-color: {c['panel_hover']};
                color: {c['accent']};
            }}
            QPushButton[active="true"] {{
                background-color: {c['accent']};
                color: #ffffff;
                font-weight: bold;
            }}
        """)
        
        # Clear existing layout if re-setting UI
        if self.layout():
            old_layout = self.layout()
            while old_layout.count():
                item = old_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            layout = old_layout
        else:
            layout = QVBoxLayout()
            self.setLayout(layout)
            
        layout.setContentsMargins(10, 15, 10, 15)
        layout.setSpacing(6)
        
        title_lbl = QLabel("NAVIGATION")
        title_lbl.setStyleSheet(f"color: {c['text_sub']}; font-size: 11px; font-weight: bold; padding: 4px 8px;")
        layout.addWidget(title_lbl)
        
        self.buttons = []
        for text, index, icon_name in self.NAV_ITEMS:
            btn = QPushButton(f"  {text}")
            btn.setIcon(qta.icon(icon_name, color=c['text']))
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda checked=False, idx=index: self._on_btn_clicked(idx))
            self.buttons.append(btn)
            layout.addWidget(btn)
        
        layout.addStretch()
        self.set_active_index(self.active_index)

    def _on_btn_clicked(self, index):
        self.set_active_index(index)
        self.nav_changed.emit(index)

    def set_active_index(self, index):
        self.active_index = index
        c = get_colors()
        for idx, btn in enumerate(self.buttons):
            is_active = (idx == index)
            btn.setProperty("active", "true" if is_active else "false")
            icon_color = "#ffffff" if is_active else c['text']
            icon_name = self.NAV_ITEMS[idx][2]
            btn.setIcon(qta.icon(icon_name, color=icon_color))
            btn.style().unpolish(btn)
            btn.style().polish(btn)
