# ui/scanner_tab.py
import socket
import ipaddress
import qtawesome as qta
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel, QLineEdit, QProgressBar, QComboBox,
    QHeaderView, QFileDialog, QMessageBox, QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush, QFont

from core.port_scanner import PortScannerThread, parse_ports_input
from core.auth_db import auth_db
from config import get_colors

def get_default_gateway_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except Exception:
        return "192.168.1.1"

class StatCard(QFrame):
    def __init__(self, title, value="0", color=None):
        super().__init__()
        self.color = color or "#00e5ff"
        self._setup_ui(title, value)
    
    def _setup_ui(self, title, value):
        c = get_colors()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-left: 4px solid {self.color};
                border-radius: 8px;
                padding: 8px 12px;
            }}
            QLabel#TitleLbl {{
                color: {c['text_sub']};
                font-size: 11px;
                font-weight: bold;
            }}
            QLabel#ValueLbl {{
                color: {self.color};
                font-size: 20px;
                font-weight: bold;
            }}
        """)
        lay = QVBoxLayout()
        lay.setContentsMargins(4, 4, 4, 4)
        self.lbl_title = QLabel(title)
        self.lbl_title.setObjectName("TitleLbl")
        self.lbl_value = QLabel(value)
        self.lbl_value.setObjectName("ValueLbl")
        lay.addWidget(self.lbl_title)
        lay.addWidget(self.lbl_value)
        self.setLayout(lay)
    
    def set_value(self, v):
        self.lbl_value.setText(str(v))

class ScannerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = None
        self.open_ports_count = 0
        self.critical_risk_count = 0
        self.secure_ports_count = 0
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        
        # 1. Top Stat Cards
        self.card_total    = StatCard("🔓 Total Open Ports", "0", c['accent'])
        self.card_critical = StatCard("🔴 Critical / High Risk", "0", c['danger'])
        self.card_secure   = StatCard("🟢 Encrypted / Secure", "0", c['success'])
        
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        cards_layout.addWidget(self.card_total)
        cards_layout.addWidget(self.card_critical)
        cards_layout.addWidget(self.card_secure)
        
        # 2. Target IP & Mode Toolbar
        self.input_ip = QLineEdit()
        self.input_ip.setPlaceholderText("Target IP Address (e.g., 192.168.8.1)")
        
        self.btn_gw = QPushButton(" Gateway")
        self.btn_gw.setIcon(qta.icon('fa5s.broadcast-tower', color='white'))
        self.btn_gw.clicked.connect(self._fill_gateway_ip)
        
        self.combo_mode = QComboBox()
        self.combo_mode.addItems([
            "Quick Scan (Top 25 Ports)",
            "Common Ports (Top 50 Services)",
            "Standard Range (1-1024)",
            "Custom Range (Specify below)"
        ])
        self.combo_mode.currentTextChanged.connect(self._on_mode_change)
        
        self.btn_scan = QPushButton(" Scan Open Ports")
        self.btn_scan.setIcon(qta.icon('fa5s.unlock-alt', color='white'))
        self.btn_scan.clicked.connect(self.start_scan)
        
        self.btn_stop = QPushButton(" Stop")
        self.btn_stop.setIcon(qta.icon('fa5s.stop', color='white'))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        
        self.btn_export_csv = QPushButton(" CSV")
        self.btn_export_csv.setIcon(qta.icon('fa5s.file-csv', color='white'))
        self.btn_export_csv.clicked.connect(self._export_csv)

        self.input_custom = QLineEdit()
        self.input_custom.setPlaceholderText("Custom ports e.g. 80, 443, 8000-8080")
        self.input_custom.setVisible(False)
        
        self.lbl_status = QLabel("Ready")
        
        top = QHBoxLayout()
        top.addWidget(self.input_ip, stretch=2)
        top.addWidget(self.btn_gw)
        top.addWidget(self.combo_mode)
        top.addWidget(self.btn_scan)
        top.addWidget(self.btn_stop)
        top.addWidget(self.btn_export_csv)
        top.addWidget(self.lbl_status, stretch=1)
        
        # 3. Formatted Progress Bar
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(18)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {c['border']};
                border-radius: 6px;
                text-align: center;
                color: {c['text']};
                font-weight: bold;
                background-color: {c['bg']};
            }}
            QProgressBar::chunk {{
                background-color: {c['accent']};
                border-radius: 5px;
            }}
        """)
        
        # 4. Proportional Table Columns Layout
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Target IP", "Port Number", "Protocol",
            "Service & Banner", "Risk Rating", "Security Assessment & Recommendation"
        ])
        self.table.verticalHeader().setVisible(False)  # Hide duplicate vertical row index
        
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        
        self.table.setColumnWidth(0, 130)
        self.table.setColumnWidth(1, 95)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 130)
        
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)
        root.addLayout(cards_layout)
        root.addLayout(top)
        root.addWidget(self.input_custom)
        root.addWidget(self.progress)
        root.addWidget(self.table)
        self.setLayout(root)
    
    def _fill_gateway_ip(self):
        gw = get_default_gateway_ip()
        self.input_ip.setText(gw)

    def _on_mode_change(self, mode_str):
        self.input_custom.setVisible("Custom Range" in mode_str)
    
    def start_scan(self):
        user = auth_db.get_current_user_session()
        if user and user.get("role") == "Viewer":
            QMessageBox.warning(self, "Access Denied", "⚠️ Viewers are not permitted to execute active port/network scans.")
            return

        ip = self.input_ip.text().strip()
        if not ip:
            self.lbl_status.setText("❌ Please enter an IP Address")
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.lbl_status.setText("❌ Target must be a valid IP address")
            return
        
        mode_str = self.combo_mode.currentText()
        custom_input = self.input_custom.text().strip()
        ports_to_scan = parse_ports_input(mode_str, custom_input)
        if not ports_to_scan:
            self.lbl_status.setText("❌ Invalid port range or scan exceeds the 4096-port limit")
            return
        
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.open_ports_count = 0
        self.critical_risk_count = 0
        self.secure_ports_count = 0
        self._update_stat_cards()
        
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.lbl_status.setText(f"Scanning {len(ports_to_scan)} ports...")
        
        self.scanner = PortScannerThread(ip, ports_to_scan)
        self.scanner.port_open.connect(self._add_port)
        self.scanner.progress.connect(self._on_progress)
        self.scanner.finished_scan.connect(self._done)
        self.scanner.start()
    
    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_status.setText("Scan Stopped")

    def _add_port(self, port, service, risk_lvl, color_cat, details):
        c = get_colors()
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        self.open_ports_count += 1
        if color_cat == "danger":
            self.critical_risk_count += 1
            fg_color = QColor(c['danger'])
            bg_color = QColor(180, 20, 20, 60)
            icon = qta.icon('fa5s.exclamation-triangle', color=c['danger'])
        elif color_cat == "warning":
            fg_color = QColor(c['warning'])
            bg_color = QColor(100, 80, 0, 40)
            icon = qta.icon('fa5s.exclamation-circle', color=c['warning'])
        elif color_cat == "success":
            self.secure_ports_count += 1
            fg_color = QColor(c['success'])
            bg_color = None
            icon = qta.icon('fa5s.shield-alt', color=c['success'])
        else:
            fg_color = QColor(c['text'])
            bg_color = None
            icon = qta.icon('fa5s.info-circle', color=c['accent'])
            
        self._update_stat_cards()
        
        item_ip = QTableWidgetItem(self.input_ip.text().strip())
        item_port = QTableWidgetItem(str(port))
        item_proto = QTableWidgetItem("TCP")
        item_svc = QTableWidgetItem(service)
        
        item_risk = QTableWidgetItem(risk_lvl)
        item_risk.setIcon(icon)
        item_risk.setForeground(fg_color)
        
        item_details = QTableWidgetItem(details)
        item_details.setForeground(fg_color)
        
        items = [item_ip, item_port, item_proto, item_svc, item_risk, item_details]
        for col_idx, item in enumerate(items):
            if bg_color:
                item.setBackground(QBrush(bg_color))
            self.table.setItem(r, col_idx, item)
    
    def _update_stat_cards(self):
        self.card_total.set_value(str(self.open_ports_count))
        self.card_critical.set_value(str(self.critical_risk_count))
        self.card_secure.set_value(str(self.secure_ports_count))

    def _on_progress(self, done, total):
        pct = int(done / total * 100)
        self.progress.setValue(pct)
        self.progress.setFormat(f"%p% Completed ({done}/{total} Ports Scanned)")

    def _done(self, ports):
        self.lbl_status.setText(f"✅ Found {len(ports)} open ports")
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Port Scan Report", "port_scan_report.csv", "CSV Files (*.csv)")
        if path:
            import csv
            with open(path, mode="w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Target IP", "Port Number", "Protocol", "Service & Banner", "Risk Rating", "Security Recommendation"])
                for r in range(self.table.rowCount()):
                    row_data = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(6)]
                    writer.writerow(row_data)
            QMessageBox.information(self, "Export Complete", f"Port Scan Report successfully saved to:\n{path}")
