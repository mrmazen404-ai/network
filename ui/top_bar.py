# ui/top_bar.py
import socket
import ctypes
import os
import qtawesome as qta
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton, QComboBox, QFileDialog, QMessageBox)
from PySide6.QtCore import Signal as pyqtSignal, Qt, QPoint
import config
from config import APP_NAME, APP_VERSION, THEMES, get_colors
from core.exporter import export_alerts_to_pdf, export_alerts_to_csv, export_packets_to_pcap

def is_admin():
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class TopBar(QFrame):
    theme_changed = pyqtSignal(str)
    direction_toggled = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("TopBar")
        self._drag_pos = QPoint()
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QFrame#TopBar {{
                background-color: {c['panel']};
                border-bottom: 2px solid {c['border']};
                padding: 4px 12px;
            }}
            QLabel#AppTitle {{
                font-size: 15px;
                font-weight: bold;
                color: {c['accent']};
            }}
            QLabel#Badge {{
                background-color: {c['card_bg']};
                color: {c['text']};
                border: 1px solid {c['border']};
                border-radius: 4px;
                padding: 3px 8px;
                font-size: 11px;
            }}
            QComboBox {{
                background-color: {c['bg']};
                color: {c['text']};
                border: 1px solid {c['border']};
                border-radius: 4px;
                padding: 3px 8px;
            }}
            QPushButton#WinControlBtn {{
                background-color: transparent;
                color: {c['text']};
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton#WinControlBtn:hover {{
                background-color: {c['panel_hover']};
            }}
            QPushButton#CloseWinBtn {{
                background-color: transparent;
                color: {c['text']};
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton#CloseWinBtn:hover {{
                background-color: {c['danger']};
                color: white;
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
            layout = QHBoxLayout()
            self.setLayout(layout)
            
        layout.setContentsMargins(8, 4, 8, 4)
        
        # Branding
        self.lbl_title = QLabel(f" {APP_NAME} v{APP_VERSION}")
        self.lbl_title.setObjectName("AppTitle")
        
        # Status Badges
        self.lbl_status = QLabel("System Secure")
        self.lbl_status.setObjectName("Badge")
        
        ip_str = get_local_ip()
        self.lbl_ip = QLabel(f"IP: {ip_str}")
        self.lbl_ip.setObjectName("Badge")
        
        admin_str = "Admin" if is_admin() else "User"
        self.lbl_admin = QLabel(admin_str)
        self.lbl_admin.setObjectName("Badge")
        
        # Audio Mute/Unmute Toggle
        self.btn_audio = QPushButton(" Audio On")
        self.btn_audio.setIcon(qta.icon('fa5s.volume-up', color='white'))
        self.btn_audio.clicked.connect(self._toggle_audio)
        
        # Export Actions
        self.btn_export_pcap = QPushButton(" PCAP")
        self.btn_export_pcap.setIcon(qta.icon('fa5s.download', color='white'))
        self.btn_export_pcap.clicked.connect(self._export_pcap)
        
        self.btn_export_pdf = QPushButton(" PDF")
        self.btn_export_pdf.setIcon(qta.icon('fa5s.file-pdf', color='white'))
        self.btn_export_pdf.clicked.connect(self._export_pdf)
        
        self.btn_export_csv = QPushButton(" CSV")
        self.btn_export_csv.setIcon(qta.icon('fa5s.file-csv', color='white'))
        self.btn_export_csv.clicked.connect(self._export_csv)
        
        # Theme Switcher
        self.combo_theme = QComboBox()
        self.combo_theme.addItems(list(THEMES.keys()))
        self.combo_theme.currentTextChanged.connect(self._on_theme_change)
        
        # Toggle Layout Direction
        self.btn_dir = QPushButton(" RTL/LTR")
        self.btn_dir.setIcon(qta.icon('fa5s.exchange-alt', color='white'))
        self.btn_dir.clicked.connect(self.direction_toggled.emit)
        
        # Custom Frameless Window Controls
        self.btn_min = QPushButton()
        self.btn_min.setObjectName("WinControlBtn")
        self.btn_min.setIcon(qta.icon('fa5s.minus', color='white'))
        self.btn_min.setToolTip("Minimize Window")
        self.btn_min.clicked.connect(lambda: self.window().showMinimized())
        
        self.btn_max = QPushButton()
        self.btn_max.setObjectName("WinControlBtn")
        self.btn_max.setIcon(qta.icon('fa5s.expand', color='white'))
        self.btn_max.setToolTip("Maximize / Restore Window")
        self.btn_max.clicked.connect(self._toggle_maximize)
        
        self.btn_close = QPushButton()
        self.btn_close.setObjectName("CloseWinBtn")
        self.btn_close.setIcon(qta.icon('fa5s.times', color='white'))
        self.btn_close.setToolTip("Close Application")
        self.btn_close.clicked.connect(lambda: self.window().close())

        layout.addWidget(self.lbl_title)
        layout.addSpacing(10)
        layout.addWidget(self.lbl_status)
        layout.addWidget(self.lbl_ip)
        layout.addWidget(self.lbl_admin)
        layout.addStretch()
        layout.addWidget(self.btn_audio)
        layout.addWidget(self.btn_export_pcap)
        layout.addWidget(self.btn_export_pdf)
        layout.addWidget(self.btn_export_csv)
        layout.addSpacing(6)
        layout.addWidget(QLabel("Theme:"))
        layout.addWidget(self.combo_theme)
        layout.addWidget(self.btn_dir)
        layout.addSpacing(10)
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)
    
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self._drag_pos:
            self.window().move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def _toggle_maximize(self):
        win = self.window()
        if win.isMaximized():
            win.showNormal()
            self.btn_max.setIcon(qta.icon('fa5s.expand', color='white'))
        else:
            win.showMaximized()
            self.btn_max.setIcon(qta.icon('fa5s.compress', color='white'))

    def _toggle_audio(self):
        config.ENABLE_AUDIO_ALERTS = not config.ENABLE_AUDIO_ALERTS
        c = get_colors()
        if config.ENABLE_AUDIO_ALERTS:
            self.btn_audio.setText(" Audio On")
            self.btn_audio.setIcon(qta.icon('fa5s.volume-up', color='white'))
        else:
            self.btn_audio.setText(" Muted")
            self.btn_audio.setIcon(qta.icon('fa5s.volume-mute', color=c['text_sub']))

    def set_threat_status(self, is_threat=True, msg=""):
        c = get_colors()
        if is_threat:
            self.lbl_status.setText(f"ALERT: {msg[:25]}")
            self.lbl_status.setStyleSheet(f"background-color: {c['danger']}; color: white; font-weight: bold; border-radius: 4px; padding: 3px 8px;")
        else:
            self.lbl_status.setText("System Secure")
            self.lbl_status.setStyleSheet(f"background-color: {c['card_bg']}; color: {c['text']}; border: 1px solid {c['border']}; border-radius: 4px; padding: 3px 8px;")

    def _on_theme_change(self, theme_name):
        self.theme_changed.emit(theme_name)

    def _export_pcap(self):
        main_win = self.window()
        pkts = []
        if hasattr(main_win, 'tab_dashboard') and main_win.tab_dashboard.sniffer:
            pkts = main_win.tab_dashboard.sniffer.get_captured_packets()
        elif hasattr(main_win, 'tab_packets') and main_win.tab_packets.sniffer:
            pkts = main_win.tab_packets.sniffer.get_captured_packets()
            
        if not pkts:
            QMessageBox.warning(self, "Export PCAP", "No captured network packets available to export.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save Captured Traffic (Wireshark PCAP)", "network_capture.pcap", "PCAP Files (*.pcap)")
        if path:
            try:
                res = export_packets_to_pcap(pkts, path)
                QMessageBox.information(self, "PCAP Export Complete", f"Successfully exported {len(pkts)} raw packets to:\n{res}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save PCAP file:\n{e}")

    def _export_pdf(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Incident Report PDF", "alerts_report.pdf", "PDF Files (*.pdf)")
        if path:
            res = export_alerts_to_pdf(path)
            QMessageBox.information(self, "Export Complete", f"Report successfully saved to:\n{res}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Alerts CSV", "alerts_data.csv", "CSV Files (*.csv)")
        if path:
            res = export_alerts_to_csv(path)
            QMessageBox.information(self, "Export Complete", f"CSV successfully saved to:\n{res}")
