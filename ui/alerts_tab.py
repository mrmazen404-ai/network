# ui/alerts_tab.py
import qtawesome as qta
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel, QLineEdit, QComboBox, QHeaderView,
    QFileDialog, QMessageBox, QFrame, QDialog, QGridLayout, QTextEdit
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush, QFont, QAction

from core.database import db
from core.exporter import export_alerts_to_pdf, export_alerts_to_csv
from config import get_colors

class IncidentDetailDialog(QDialog):
    """Detailed Incident Response Modal Dialog for Threat Analysis"""
    def __init__(self, alert_data, parent=None):
        super().__init__(parent)
        self.alert = alert_data
        self.setWindowTitle(f"Security Incident Investigation - #{alert_data.get('id')} ({alert_data.get('type')})")
        self.resize(560, 480)
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QDialog {{ background-color: {c['bg']}; color: {c['text']}; }}
            QLabel {{ font-size: 12px; }}
            QTextEdit {{
                background-color: {c['panel']};
                color: {c['text']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 6px;
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(12)
        
        grid = QGridLayout()
        grid.setSpacing(10)
        
        sev = self.alert.get('severity', 'LOW')
        sev_color = {
            "CRITICAL": c['danger'],
            "HIGH":     "#ff8800",
            "MEDIUM":   c['warning'],
            "LOW":      c['text']
        }.get(sev, c['text'])
        
        grid.addWidget(QLabel("Incident ID:"), 0, 0)
        grid.addWidget(QLabel(f"<b>#{self.alert.get('id', 'N/A')}</b>"), 0, 1)
        
        grid.addWidget(QLabel("Timestamp:"), 1, 0)
        grid.addWidget(QLabel(f"<b>{self.alert.get('timestamp', '')}</b>"), 1, 1)
        
        grid.addWidget(QLabel("Threat Category:"), 2, 0)
        grid.addWidget(QLabel(f"<b>{self.alert.get('type', '')}</b>"), 2, 1)
        
        grid.addWidget(QLabel("Severity Rating:"), 3, 0)
        lbl_sev = QLabel(f"<b>{sev}</b>")
        lbl_sev.setStyleSheet(f"color: {sev_color}; font-weight: bold; font-size: 13px;")
        grid.addWidget(lbl_sev, 3, 1)
        
        grid.addWidget(QLabel("Attacker / Source IP:"), 4, 0)
        grid.addWidget(QLabel(f"<b>{self.alert.get('src_ip', 'N/A')}</b>"), 4, 1)
        
        grid.addWidget(QLabel("Target / Destination IP:"), 5, 0)
        grid.addWidget(QLabel(f"<b>{self.alert.get('dst_ip', 'N/A')}</b>"), 5, 1)
        
        layout.addLayout(grid)
        
        # Details & Message
        layout.addWidget(QLabel("<b>Incident Details & Payload Signature:</b>"))
        txt_msg = QTextEdit(self.alert.get('message', ''))
        txt_msg.setReadOnly(True)
        txt_msg.setMaximumHeight(80)
        layout.addWidget(txt_msg)
        
        # Recommended Mitigation
        layout.addWidget(QLabel("<b>Security Mitigation & Action Recommended:</b>"))
        mitigation_str = "Inspect Source IP and isolate host if unrecognized. Enforce Firewall ACL rules or tag as Rogue."
        if "ARP" in self.alert.get('type', ''):
            mitigation_str = "CRITICAL: Potential Man-In-The-Middle / Spoofing Attack! Enable Static ARP inspection on Router & Switch."
        elif "SYN" in self.alert.get('type', '') or "DoS" in self.alert.get('type', ''):
            mitigation_str = "HIGH: Denial of Service / SYN Flood Traffic! Rate-limit TCP connections from source IP or block in Firewall."
        
        lbl_mit = QLabel(f"💡 {mitigation_str}")
        lbl_mit.setStyleSheet(f"color: {sev_color}; font-style: italic;")
        lbl_mit.setWordWrap(True)
        layout.addWidget(lbl_mit)
        
        # Action Buttons
        btn_layout = QHBoxLayout()
        
        self.btn_scan = QPushButton(" Scan Attacker Ports")
        self.btn_scan.setIcon(qta.icon('fa5s.unlock-alt', color='white'))
        self.btn_scan.clicked.connect(self._scan_attacker)
        
        self.btn_export = QPushButton(" Export PDF Report")
        self.btn_export.setIcon(qta.icon('fa5s.file-pdf', color='white'))
        self.btn_export.clicked.connect(self._export_pdf)
        
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.accept)
        
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_export)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def _scan_attacker(self):
        self.accept()
        ip = self.alert.get('src_ip')
        if ip and ip != "N/A" and ip != "LAN":
            main_win = self.window()
            if hasattr(main_win, 'sidebar') and hasattr(main_win, 'pages') and hasattr(main_win, 'tab_scanner'):
                main_win.sidebar.set_active_index(4)
                main_win.pages.setCurrentIndex(4)
                main_win.tab_scanner.input_ip.setText(ip)
                main_win.tab_scanner.start_scan()

    def _export_pdf(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Incident Report PDF", f"incident_{self.alert.get('id')}.pdf", "PDF Files (*.pdf)")
        if path:
            res = export_alerts_to_pdf(path)
            QMessageBox.information(self, "Export Complete", f"Incident report exported successfully to:\n{res}")

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

class AlertsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_alerts_data = []
        self._setup_ui()
        self.load()
    
    def _setup_ui(self):
        c = get_colors()
        
        # 1. Top Stat Cards
        self.card_critical = StatCard("🔴 Critical Threats", "0", c['danger'])
        self.card_high     = StatCard("🟧 High Severity",   "0", "#ff8800")
        self.card_medium   = StatCard("🟡 Medium Warnings", "0", c['warning'])
        self.card_total    = StatCard("📊 Total Incidents", "0", c['accent'])
        
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        cards_layout.addWidget(self.card_critical)
        cards_layout.addWidget(self.card_high)
        cards_layout.addWidget(self.card_medium)
        cards_layout.addWidget(self.card_total)
        
        # 2. Controls & Search Toolbar
        self.input_search = QLineEdit()
        self.input_search.setPlaceholderText("🔍 Search Incident Log (by IP, Threat Type, Message)...")
        self.input_search.textChanged.connect(self._apply_filter)
        
        self.combo_severity = QComboBox()
        self.combo_severity.addItems([
            "All Severity Levels",
            "🔴 CRITICAL Only",
            "🟧 HIGH Only",
            "🟡 MEDIUM Only"
        ])
        self.combo_severity.currentTextChanged.connect(self._apply_filter)
        
        self.btn_export_pdf = QPushButton(" Export PDF")
        self.btn_export_pdf.setIcon(qta.icon('fa5s.file-pdf', color='white'))
        self.btn_export_pdf.clicked.connect(self._export_pdf)
        
        self.btn_export_csv = QPushButton(" Export CSV")
        self.btn_export_csv.setIcon(qta.icon('fa5s.file-csv', color='white'))
        self.btn_export_csv.clicked.connect(self._export_csv)
        
        self.btn_refresh = QPushButton(" Refresh")
        self.btn_refresh.setIcon(qta.icon('fa5s.sync-alt', color='white'))
        self.btn_refresh.clicked.connect(self.load)
        
        self.btn_clear = QPushButton(" Clear Log")
        self.btn_clear.setIcon(qta.icon('fa5s.trash-alt', color='white'))
        self.btn_clear.clicked.connect(self.clear)
        
        top_bar = QHBoxLayout()
        top_bar.addWidget(self.input_search, stretch=2)
        top_bar.addWidget(self.combo_severity)
        top_bar.addWidget(self.btn_export_pdf)
        top_bar.addWidget(self.btn_export_csv)
        top_bar.addWidget(self.btn_refresh)
        top_bar.addWidget(self.btn_clear)
        
        # 3. Proportional Main Incidents Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "#", "Timestamp", "Threat Category", "Severity",
            "Source IP", "Destination IP", "Incident Details & Mitigation"
        ])
        self.table.verticalHeader().setVisible(False)  # Hide duplicate vertical row index
        
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        
        self.table.setColumnWidth(1, 150)  # Full timestamp display without truncation ...
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 110)
        self.table.setColumnWidth(4, 130)
        self.table.setColumnWidth(5, 130)
        
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemDoubleClicked.connect(self._on_row_double_click)
        
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)
        root.addLayout(cards_layout)
        root.addLayout(top_bar)
        root.addWidget(self.table)
        self.setLayout(root)
    
    def load(self):
        self.all_alerts_data = db.get_alerts(300)
        self._update_stat_cards()
        self._apply_filter()

    def _update_stat_cards(self):
        total    = len(self.all_alerts_data)
        critical = sum(1 for a in self.all_alerts_data if a.get("severity") == "CRITICAL")
        high     = sum(1 for a in self.all_alerts_data if a.get("severity") == "HIGH")
        medium   = sum(1 for a in self.all_alerts_data if a.get("severity") == "MEDIUM")
        
        self.card_total.set_value(str(total))
        self.card_critical.set_value(str(critical))
        self.card_high.set_value(str(high))
        self.card_medium.set_value(str(medium))

    def _apply_filter(self):
        c = get_colors()
        self.table.setRowCount(0)
        
        search_txt = self.input_search.text().strip().lower()
        sev_filter = self.combo_severity.currentText()
        
        for a in self.all_alerts_data:
            sev = a.get("severity", "LOW")
            atype = a.get("type", "")
            src = a.get("src_ip", "")
            dst = a.get("dst_ip", "")
            msg = a.get("message", "")
            ts  = a.get("timestamp", "")
            
            # Severity Filter
            if "CRITICAL Only" in sev_filter and sev != "CRITICAL":
                continue
            if "HIGH Only" in sev_filter and sev != "HIGH":
                continue
            if "MEDIUM Only" in sev_filter and sev != "MEDIUM":
                continue
            
            # Keyword Filter
            combo_str = f"{atype} {sev} {src} {dst} {msg} {ts}".lower()
            if search_txt and search_txt not in combo_str:
                continue
            
            self._insert_row(a)

    def _insert_row(self, a):
        c = get_colors()
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        sev = a.get("severity", "LOW")
        color = {
            "CRITICAL": QColor(c['danger']),
            "HIGH":     QColor("#ff8800"),
            "MEDIUM":   QColor(c['warning']),
            "LOW":      QColor(c['text']),
        }.get(sev, QColor(c['text']))
        
        it_id = QTableWidgetItem(str(a.get("id", r+1)))
        it_ts = QTableWidgetItem(str(a.get("timestamp", "")))
        
        it_type = QTableWidgetItem(str(a.get("type", "")))
        it_type.setIcon(qta.icon('fa5s.exclamation-triangle', color=color))
        it_type.setForeground(color)
        
        it_sev = QTableWidgetItem(sev)
        it_sev.setForeground(color)
        
        it_src = QTableWidgetItem(str(a.get("src_ip", "")))
        it_dst = QTableWidgetItem(str(a.get("dst_ip", "")))
        it_msg = QTableWidgetItem(str(a.get("message", "")))
        
        items = [it_id, it_ts, it_type, it_sev, it_src, it_dst, it_msg]
        for col_idx, item in enumerate(items):
            if sev in ("CRITICAL", "HIGH"):
                item.setForeground(color)
            self.table.setItem(r, col_idx, item)
            
        # Attach raw alert dict to item 0
        it_id.setData(Qt.UserRole, a)

    def add_alert(self, alert):
        self.load()

    def _on_row_double_click(self, item):
        row = item.row()
        item_0 = self.table.item(row, 0)
        alert_data = item_0.data(Qt.UserRole) if item_0 else None
        if alert_data:
            dialog = IncidentDetailDialog(alert_data, self)
            dialog.exec_()

    def clear(self):
        res = QMessageBox.question(self, "Clear Log History", "Are you sure you want to clear all threat incident logs?",
                                   QMessageBox.Yes | QMessageBox.No)
        if res == QMessageBox.Yes:
            db.clear_alerts()
            self.load()

    def _export_pdf(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Security Incidents PDF", "incident_report.pdf", "PDF Files (*.pdf)")
        if path:
            res = export_alerts_to_pdf(path)
            QMessageBox.information(self, "Export Complete", f"Incident Report exported successfully to:\n{res}")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Incident Log CSV", "incidents_log.csv", "CSV Files (*.csv)")
        if path:
            res = export_alerts_to_csv(path)
            QMessageBox.information(self, "Export Complete", f"Incident Log exported successfully to:\n{res}")
