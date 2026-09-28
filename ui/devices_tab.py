# ui/devices_tab.py
import socket
import platform
import subprocess
import webbrowser
import time
import qtawesome as qta
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                              QTableWidget, QTableWidgetItem, QLabel, QLineEdit,
                              QComboBox, QMenu, QMessageBox, QDialog, QTextEdit,
                              QGridLayout, QFrame, QFileDialog)
from PySide6.QtCore import Qt, QTimer, QThread, Signal as pyqtSignal
from PySide6.QtGui import QColor, QAction

from core.scanner import DeviceScannerThread
from core.database import db
from core.exporter import export_devices_to_csv
from config import get_colors

def ping_host(ip, timeout_ms=800):
    try:
        start = time.time()
        param = "-n" if platform.system().lower() == "windows" else "-c"
        res = subprocess.run(["ping", param, "1", "-w", str(timeout_ms), ip],
                             capture_output=True, text=True, timeout=1.5)
        rtt = (time.time() - start) * 1000.0
        return ip, (res.returncode == 0), rtt
    except Exception:
        return ip, False, 0.0

class DeviceStatusPingWorker(QThread):
    status_updated = pyqtSignal(dict)
    
    def __init__(self, ip_list):
        super().__init__()
        self.ip_list = ip_list
    
    def run(self):
        results = {}
        if not self.ip_list:
            self.status_updated.emit(results)
            return
            
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in self.ip_list}
            for future in as_completed(futures):
                ip, is_online, rtt = future.result()
                results[ip] = (is_online, rtt)
                
        self.status_updated.emit(results)

class DeviceDetailDialog(QDialog):
    def __init__(self, device_data, is_online=False, rtt=0, parent=None):
        super().__init__(parent)
        self.device = device_data
        self.is_online = is_online
        self.rtt = rtt
        self.setWindowTitle(f"Device Profile - {device_data.get('ip')} ({device_data.get('mac')})")
        self.resize(560, 540)
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QDialog {{ background-color: {c['bg']}; color: {c['text']}; }}
            QLabel {{ font-size: 12px; }}
            QLineEdit, QComboBox, QTextEdit {{
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
        
        status_str = f"ONLINE ({self.rtt:.1f} ms)" if self.is_online else "OFFLINE"
        
        grid.addWidget(QLabel("Live Status:"), 0, 0)
        grid.addWidget(QLabel(f"<b>{status_str}</b>"), 0, 1)
        
        grid.addWidget(QLabel("IP Address:"), 1, 0)
        grid.addWidget(QLabel(f"<b>{self.device.get('ip', '')}</b>"), 1, 1)
        
        grid.addWidget(QLabel("MAC Address:"), 2, 0)
        grid.addWidget(QLabel(f"<b>{self.device.get('mac', '')}</b>"), 2, 1)
        
        grid.addWidget(QLabel("Vendor / Hardware:"), 3, 0)
        grid.addWidget(QLabel(self.device.get('vendor', 'Unknown')), 3, 1)
        
        grid.addWidget(QLabel("Device Category / OS:"), 4, 0)
        grid.addWidget(QLabel(self.device.get('device_type', 'Network Host')), 4, 1)
        
        grid.addWidget(QLabel("Hostname:"), 5, 0)
        grid.addWidget(QLabel(self.device.get('hostname') or "N/A"), 5, 1)
        
        grid.addWidget(QLabel("First Seen:"), 6, 0)
        grid.addWidget(QLabel(self.device.get('first_seen', 'N/A')), 6, 1)
        
        grid.addWidget(QLabel("Last Seen:"), 7, 0)
        grid.addWidget(QLabel(self.device.get('last_seen', 'N/A')), 7, 1)
        
        grid.addWidget(QLabel("Custom Alias / Name:"), 8, 0)
        self.input_alias = QLineEdit(self.device.get('alias', ''))
        self.input_alias.setPlaceholderText("e.g. CEO Laptop, Reception Printer")
        grid.addWidget(self.input_alias, 8, 1)
        
        grid.addWidget(QLabel("Security Tag:"), 9, 0)
        self.combo_status = QComboBox()
        self.combo_status.addItems(["Trusted", "Unknown", "Rogue / Suspicious"])
        curr_status = self.device.get('trust_status', 'Unknown')
        if "Trusted" in curr_status:
            self.combo_status.setCurrentIndex(0)
        elif "Rogue" in curr_status or "Suspicious" in curr_status:
            self.combo_status.setCurrentIndex(2)
        else:
            self.combo_status.setCurrentIndex(1)
        grid.addWidget(self.combo_status, 9, 1)
        
        grid.addWidget(QLabel("Admin Notes:"), 10, 0)
        self.txt_notes = QTextEdit(self.device.get('notes', ''))
        self.txt_notes.setMaximumHeight(65)
        grid.addWidget(self.txt_notes, 10, 1)
        
        layout.addLayout(grid)
        
        layout.addWidget(QLabel("<b>Scanned Open Ports:</b>"))
        open_ports = db.get_open_ports(self.device.get('ip'))
        if open_ports:
            ports_str = ", ".join([f"{p['port']} ({p['service']})" for p in open_ports])
        else:
            ports_str = "No open ports scanned yet."
        lbl_ports = QLabel(ports_str)
        lbl_ports.setStyleSheet(f"color: {c['text_sub']}; font-style: italic;")
        lbl_ports.setWordWrap(True)
        layout.addWidget(lbl_ports)
        
        btn_layout = QHBoxLayout()
        
        self.btn_ping = QPushButton(" Ping Check")
        self.btn_ping.setIcon(qta.icon('fa5s.satellite-dish', color='white'))
        self.btn_ping.clicked.connect(self._ping)
        
        self.btn_scan_ports = QPushButton(" Port Scan")
        self.btn_scan_ports.setIcon(qta.icon('fa5s.unlock-alt', color='white'))
        self.btn_scan_ports.clicked.connect(self._scan_ports)
        
        self.btn_web = QPushButton(" Open Web UI")
        self.btn_web.setIcon(qta.icon('fa5s.globe', color='white'))
        self.btn_web.clicked.connect(self._open_web)
        
        self.btn_save = QPushButton(" Save Profile")
        self.btn_save.setIcon(qta.icon('fa5s.save', color='white'))
        self.btn_save.clicked.connect(self._save)
        
        btn_layout.addWidget(self.btn_ping)
        btn_layout.addWidget(self.btn_scan_ports)
        btn_layout.addWidget(self.btn_web)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_save)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)
    
    def _save(self):
        alias = self.input_alias.text().strip()
        status_raw = self.combo_status.currentText()
        if "Trusted" in status_raw:
            trust_status = "Trusted"
        elif "Rogue" in status_raw:
            trust_status = "Rogue / Suspicious"
        else:
            trust_status = "Unknown"
        notes = self.txt_notes.toPlainText().strip()
        
        db.update_device_meta(self.device.get('mac'), alias=alias, trust_status=trust_status, notes=notes)
        QMessageBox.information(self, "Saved", "Device profile updated successfully!")
        self.accept()
    
    def _ping(self):
        ip = self.device.get('ip')
        ip_res, success, rtt = ping_host(ip, timeout_ms=1000)
        if success:
            self.is_online = True
            self.rtt = rtt
            QMessageBox.information(self, "Ping Success", f"Device {ip} is ONLINE!\nResponse Time: {rtt:.1f} ms")
        else:
            self.is_online = False
            QMessageBox.warning(self, "Ping Failed", f"Device {ip} is UNREACHABLE / Offline")
    
    def _scan_ports(self):
        self.accept()
        main_win = self.window()
        if hasattr(main_win, 'sidebar') and hasattr(main_win, 'pages') and hasattr(main_win, 'tab_scanner'):
            main_win.sidebar.set_active_index(4)
            main_win.pages.setCurrentIndex(4)
            main_win.tab_scanner.input_ip.setText(self.device.get('ip'))
            main_win.tab_scanner.start_scan()

    def _open_web(self):
        ip = self.device.get('ip')
        webbrowser.open(f"http://{ip}")

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

class DevicesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_devices_data = []
        self.live_ping_status = {}
        self.ping_worker = None
        
        self.autoscan_timer = QTimer(self)
        self.autoscan_timer.timeout.connect(self.start_scan)
        
        self.ping_check_timer = QTimer(self)
        self.ping_check_timer.setInterval(20000)
        self.ping_check_timer.timeout.connect(self._run_background_ping_check)
        
        self._setup_ui()
        self.load_from_db()

    def set_active(self, active):
        if active:
            self.ping_check_timer.start()
        else:
            self.ping_check_timer.stop()
    
    def _setup_ui(self):
        c = get_colors()
        
        # Stat Cards
        self.card_total   = StatCard("Total LAN Devices", "0", c['accent'])
        self.card_online  = StatCard("Online Devices",    "0", c['success'])
        self.card_offline = StatCard("Offline Devices",   "0", c['danger'])
        self.card_rogue   = StatCard("Rogue / Unknown",   "0", c['warning'])
        
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        cards_layout.addWidget(self.card_total)
        cards_layout.addWidget(self.card_online)
        cards_layout.addWidget(self.card_offline)
        cards_layout.addWidget(self.card_rogue)
        
        # Filter Bar
        self.input_search = QLineEdit()
        self.input_search.setPlaceholderText(" Quick Search (by IP, MAC, Vendor, Hostname, Alias)...")
        self.input_search.textChanged.connect(self._apply_filter)
        
        self.combo_status_filter = QComboBox()
        self.combo_status_filter.addItems([
            "All Devices (Online & Offline)",
            "Online Only",
            "Offline Only",
            "Trusted Only",
            "Rogue / Suspicious Only"
        ])
        self.combo_status_filter.currentTextChanged.connect(self._apply_filter)
        
        self.input_subnet = QLineEdit()
        self.input_subnet.setPlaceholderText("Subnet CIDR (Auto-detect e.g., 192.168.1.0/24)")
        
        self.btn_scan = QPushButton(" Scan Subnet")
        self.btn_scan.setIcon(qta.icon('fa5s.search', color='white'))
        self.btn_scan.clicked.connect(self.start_scan)
        
        self.combo_autoscan = QComboBox()
        self.combo_autoscan.addItems([
            "Auto-Scan Subnet: Off",
            "Every 30 Seconds",
            "Every 1 Minute",
            "Every 5 Minutes"
        ])
        self.combo_autoscan.currentTextChanged.connect(self._on_autoscan_change)
        
        self.btn_export = QPushButton(" Export CSV")
        self.btn_export.setIcon(qta.icon('fa5s.file-csv', color='white'))
        self.btn_export.clicked.connect(self._export_csv)
        
        self.lbl_status = QLabel("Ready")
        
        ctrl_layout1 = QHBoxLayout()
        ctrl_layout1.addWidget(self.input_search, stretch=2)
        ctrl_layout1.addWidget(self.combo_status_filter)
        ctrl_layout1.addWidget(self.btn_export)
        
        ctrl_layout2 = QHBoxLayout()
        ctrl_layout2.addWidget(self.input_subnet, stretch=2)
        ctrl_layout2.addWidget(self.btn_scan)
        ctrl_layout2.addWidget(self.combo_autoscan)
        ctrl_layout2.addWidget(self.lbl_status, stretch=1)
        
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "Live Status", "Category / OS", "Security Tag", "IP Address",
            "Custom Alias", "MAC Address", "Vendor / Hardware", "Hostname", "Last Seen"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.itemDoubleClicked.connect(self._on_row_double_click)
        
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)
        root.addLayout(cards_layout)
        root.addLayout(ctrl_layout1)
        root.addLayout(ctrl_layout2)
        root.addWidget(self.table)
        self.setLayout(root)
    
    def load_from_db(self):
        self.all_devices_data = db.get_devices()
        self._run_background_ping_check()
        self._apply_filter()

    def _run_background_ping_check(self):
        ip_list = [d.get("ip") for d in self.all_devices_data if d.get("ip")]
        if not ip_list:
            return
        
        if self.ping_worker and self.ping_worker.isRunning():
            return
            
        self.ping_worker = DeviceStatusPingWorker(ip_list)
        self.ping_worker.status_updated.connect(self._on_ping_results_received)
        self.ping_worker.start()

    def _on_ping_results_received(self, results):
        self.live_ping_status.update(results)
        self._update_stat_cards()
        self._apply_filter()

    def _is_device_online(self, device):
        ip = device.get("ip", "")
        if ip in self.live_ping_status:
            return self.live_ping_status[ip][0]
            
        last_seen_str = device.get("last_seen", "")
        try:
            last_dt = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
            return (datetime.now() - last_dt).total_seconds() < 300
        except Exception:
            return False

    def _update_stat_cards(self):
        total = len(self.all_devices_data)
        online = sum(1 for d in self.all_devices_data if self._is_device_online(d))
        offline = total - online
        rogue = sum(1 for d in self.all_devices_data if "Rogue" in d.get("trust_status", "") or "Suspicious" in d.get("trust_status", "") or "Unknown" in d.get("trust_status", ""))
        
        self.card_total.set_value(str(total))
        self.card_online.set_value(str(online))
        self.card_offline.set_value(str(offline))
        self.card_rogue.set_value(str(rogue))

    def _apply_filter(self):
        c = get_colors()
        self.table.setRowCount(0)
        
        search_txt = self.input_search.text().strip().lower()
        filter_option = self.combo_status_filter.currentText()
        
        for d in self.all_devices_data:
            ip       = d.get("ip", "")
            mac      = d.get("mac", "")
            vendor   = d.get("vendor", "")
            hostname = d.get("hostname", "")
            alias    = d.get("alias", "")
            dev_type = d.get("device_type", "Network Host")
            trust    = d.get("trust_status", "Unknown")
            is_online = self._is_device_online(d)
            
            if "Online Only" in filter_option and not is_online:
                continue
            if "Offline Only" in filter_option and is_online:
                continue
            if "Trusted Only" in filter_option and "Trusted" not in trust:
                continue
            if "Rogue" in filter_option and ("Rogue" not in trust and "Suspicious" not in trust):
                continue
            
            combo_str = f"{ip} {mac} {vendor} {hostname} {alias} {dev_type} {trust}".lower()
            if search_txt and search_txt not in combo_str:
                continue
            
            self._insert_row(d, is_online)

    def _insert_row(self, d, is_online):
        c = get_colors()
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        ip = d.get("ip", "")
        rtt_ms = self.live_ping_status.get(ip, (False, 0.0))[1]
        
        # Status
        if is_online:
            rtt_str = f" ({rtt_ms:.0f}ms)" if rtt_ms > 0 else ""
            status_item = QTableWidgetItem(f"Online{rtt_str}")
            status_item.setIcon(qta.icon('fa5s.check-circle', color=c['success']))
            status_item.setForeground(QColor(c['success']))
        else:
            status_item = QTableWidgetItem("Offline")
            status_item.setIcon(qta.icon('fa5s.times-circle', color=c['danger']))
            status_item.setForeground(QColor(c['danger']))
            
        # Category Icon
        dev_type_str = d.get("device_type", "Network Host")
        type_item = QTableWidgetItem(dev_type_str)
        if "Router" in dev_type_str or "Gateway" in dev_type_str:
            type_item.setIcon(qta.icon('fa5s.network-wired', color=c['accent']))
        elif "Printer" in dev_type_str:
            type_item.setIcon(qta.icon('fa5s.print', color=c['accent']))
        elif "Apple" in dev_type_str or "Android" in dev_type_str or "Mobile" in dev_type_str:
            type_item.setIcon(qta.icon('fa5s.mobile-alt', color=c['accent']))
        elif "Linux" in dev_type_str:
            type_item.setIcon(qta.icon('fa5b.linux', color=c['accent']))
        elif "Windows" in dev_type_str:
            type_item.setIcon(qta.icon('fa5b.windows', color=c['accent']))
        else:
            type_item.setIcon(qta.icon('fa5s.desktop', color=c['accent']))
        
        # Tag
        trust = d.get("trust_status", "Unknown")
        if "Trusted" in trust:
            tag_item = QTableWidgetItem("Trusted")
            tag_item.setIcon(qta.icon('fa5s.shield-alt', color=c['success']))
            tag_item.setForeground(QColor(c['success']))
        elif "Rogue" in trust or "Suspicious" in trust:
            tag_item = QTableWidgetItem("Rogue")
            tag_item.setIcon(qta.icon('fa5s.exclamation-triangle', color=c['danger']))
            tag_item.setForeground(QColor(c['danger']))
        else:
            tag_item = QTableWidgetItem("Unknown")
            tag_item.setIcon(qta.icon('fa5s.question-circle', color=c['warning']))
            tag_item.setForeground(QColor(c['warning']))

        it_ip = QTableWidgetItem(ip)
        it_alias = QTableWidgetItem(d.get("alias", ""))
        it_mac = QTableWidgetItem(d.get("mac", ""))
        it_vendor = QTableWidgetItem(d.get("vendor", ""))
        it_host = QTableWidgetItem(d.get("hostname", ""))
        it_seen = QTableWidgetItem(d.get("last_seen", ""))
        
        self.table.setItem(r, 0, status_item)
        self.table.setItem(r, 1, type_item)
        self.table.setItem(r, 2, tag_item)
        self.table.setItem(r, 3, it_ip)
        self.table.setItem(r, 4, it_alias)
        self.table.setItem(r, 5, it_mac)
        self.table.setItem(r, 6, it_vendor)
        self.table.setItem(r, 7, it_host)
        self.table.setItem(r, 8, it_seen)
        
        status_item.setData(Qt.UserRole, d)

    def start_scan(self):
        self.lbl_status.setText("Scanning LAN subnet...")
        self.btn_scan.setEnabled(False)
        
        subnet = self.input_subnet.text().strip() or None
        self.scanner = DeviceScannerThread(subnet)
        self.scanner.finished_scan.connect(self._done_scan)
        self.scanner.error_occurred.connect(self._err_scan)
        self.scanner.start()

    def _done_scan(self, devices):
        self.load_from_db()
        self.lbl_status.setText(f"Found {len(devices)} active devices")
        self.btn_scan.setEnabled(True)

    def _err_scan(self, msg):
        self.lbl_status.setText(f"Error: {msg}")
        self.btn_scan.setEnabled(True)

    def _on_autoscan_change(self, txt):
        if "30 Seconds" in txt:
            self.autoscan_timer.start(30000)
        elif "1 Minute" in txt:
            self.autoscan_timer.start(60000)
        elif "5 Minutes" in txt:
            self.autoscan_timer.start(300000)
        else:
            self.autoscan_timer.stop()

    def _show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        row = item.row()
        item_0 = self.table.item(row, 0)
        device = item_0.data(Qt.UserRole) if item_0 else None
        if not device:
            return
        
        ip = device.get('ip', '')
        is_online = self._is_device_online(device)
        rtt = self.live_ping_status.get(ip, (False, 0.0))[1]
        
        menu = QMenu(self)
        
        act_details = QAction(" View Full Device Profile", self)
        act_details.setIcon(qta.icon('fa5s.id-card', color='white'))
        act_details.triggered.connect(lambda: self._open_device_dialog(device, is_online, rtt))
        
        act_ports = QAction(" Scan Open Ports (Port Scanner)", self)
        act_ports.setIcon(qta.icon('fa5s.unlock-alt', color='white'))
        act_ports.triggered.connect(lambda: self._trigger_port_scan(ip))
        
        act_ping = QAction(" Ping Check (Test Latency)", self)
        act_ping.setIcon(qta.icon('fa5s.satellite-dish', color='white'))
        act_ping.triggered.connect(lambda: self._trigger_ping(ip))
        
        act_web = QAction(" Open Web Interface (http)", self)
        act_web.setIcon(qta.icon('fa5s.globe', color='white'))
        act_web.triggered.connect(lambda: webbrowser.open(f"http://{ip}"))
        
        menu_tag = QMenu(" Set Security Tag", self)
        menu_tag.setIcon(qta.icon('fa5s.shield-alt', color='white'))
        
        act_tag_trusted = QAction(" Mark as Trusted", self)
        act_tag_trusted.setIcon(qta.icon('fa5s.check', color='green'))
        act_tag_trusted.triggered.connect(lambda: self._update_trust(device.get('mac'), "Trusted"))
        
        act_tag_unknown = QAction(" Mark as Unknown", self)
        act_tag_unknown.setIcon(qta.icon('fa5s.question', color='orange'))
        act_tag_unknown.triggered.connect(lambda: self._update_trust(device.get('mac'), "Unknown"))
        
        act_tag_rogue = QAction(" Mark as Rogue / Suspicious", self)
        act_tag_rogue.setIcon(qta.icon('fa5s.exclamation', color='red'))
        act_tag_rogue.triggered.connect(lambda: self._update_trust(device.get('mac'), "Rogue / Suspicious"))
        
        menu_tag.addAction(act_tag_trusted)
        menu_tag.addAction(act_tag_unknown)
        menu_tag.addAction(act_tag_rogue)
        
        act_delete = QAction(" Remove Device Record", self)
        act_delete.setIcon(qta.icon('fa5s.trash-alt', color='red'))
        act_delete.triggered.connect(lambda: self._delete_device(device.get('mac')))
        
        menu.addAction(act_details)
        menu.addSeparator()
        menu.addAction(act_ports)
        menu.addAction(act_ping)
        menu.addAction(act_web)
        menu.addSeparator()
        menu.addMenu(menu_tag)
        menu.addSeparator()
        menu.addAction(act_delete)
        
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _on_row_double_click(self, item):
        row = item.row()
        item_0 = self.table.item(row, 0)
        device = item_0.data(Qt.UserRole) if item_0 else None
        if device:
            ip = device.get('ip', '')
            is_online = self._is_device_online(device)
            rtt = self.live_ping_status.get(ip, (False, 0.0))[1]
            self._open_device_dialog(device, is_online, rtt)

    def _open_device_dialog(self, device, is_online, rtt):
        dialog = DeviceDetailDialog(device, is_online, rtt, self)
        dialog.exec_()
        self.load_from_db()

    def _trigger_port_scan(self, ip):
        main_win = self.window()
        if hasattr(main_win, 'sidebar') and hasattr(main_win, 'pages') and hasattr(main_win, 'tab_scanner'):
            main_win.sidebar.set_active_index(4)
            main_win.pages.setCurrentIndex(4)
            main_win.tab_scanner.input_ip.setText(ip)
            main_win.tab_scanner.start_scan()

    def _trigger_ping(self, ip):
        self.lbl_status.setText(f"Pinging {ip}...")
        ip_res, success, rtt = ping_host(ip, timeout_ms=1000)
        if success:
            self.live_ping_status[ip] = (True, rtt)
            self._update_stat_cards()
            self._apply_filter()
            QMessageBox.information(self, "Ping Results", f"Device {ip} is ONLINE!\nLatency: {rtt:.1f} ms")
        else:
            self.live_ping_status[ip] = (False, 0.0)
            self._update_stat_cards()
            self._apply_filter()
            QMessageBox.warning(self, "Ping Results", f"Device {ip} is UNREACHABLE / Offline")

    def _update_trust(self, mac, trust_status):
        db.update_device_meta(mac, trust_status=trust_status)
        self.load_from_db()

    def _delete_device(self, mac):
        res = QMessageBox.question(self, "Confirm Delete", "Are you sure you want to delete this device record?",
                                   QMessageBox.Yes | QMessageBox.No)
        if res == QMessageBox.Yes:
            db.delete_device(mac)
            self.load_from_db()

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save LAN Devices Inventory", "lan_devices.csv", "CSV Files (*.csv)")
        if path:
            res = export_devices_to_csv(path)
            QMessageBox.information(self, "Export Complete", f"LAN Devices inventory successfully exported to:\n{res}")

    def closeEvent(self, event):
        self.autoscan_timer.stop()
        self.ping_check_timer.stop()
        if self.ping_worker and self.ping_worker.isRunning():
            self.ping_worker.wait(1000)
        super().closeEvent(event)
