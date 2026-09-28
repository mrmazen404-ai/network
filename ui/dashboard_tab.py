# ui/dashboard_tab.py
import qtawesome as qta
from collections import defaultdict, deque
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                              QPushButton, QGridLayout, QFrame, QProgressBar,
                              QTableWidget, QTableWidgetItem, QHeaderView)
from PySide6.QtCore import Signal as pyqtSignal, Qt, QTimer
import pyqtgraph as pg

from core.sniffer import SnifferThread
from core.detector import ThreatDetector
from core.speed_monitor import SpeedMonitorThread
from core.database import db
from config import get_colors

class StatCard(QFrame):
    def __init__(self, title, value="0", color=None):
        super().__init__()
        self.color = color or get_colors()['accent']
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
    
    def apply_style(self, color):
        self.color = color
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

    def set_value(self, v):
        self.lbl_value.setText(str(v))

class SecurityHealthScoreWidget(QFrame):
    """0-100% Enterprise Security Health Score Gauge Meter"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        c = get_colors()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 8px;
                padding: 10px;
            }}
            QLabel#ScoreTitle {{
                font-size: 12px;
                font-weight: bold;
                color: {c['text']};
            }}
            QLabel#ScoreValue {{
                font-size: 22px;
                font-weight: bold;
                color: {c['success']};
            }}
            QLabel#TipLbl {{
                font-size: 11px;
                color: {c['text_sub']};
                font-style: italic;
            }}
        """)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 6, 10, 6)
        
        vbox = QVBoxLayout()
        self.lbl_title = QLabel("Security Health Score Gauge")
        self.lbl_title.setObjectName("ScoreTitle")
        
        self.lbl_value = QLabel("100% (OPTIMAL)")
        self.lbl_value.setObjectName("ScoreValue")
        
        self.lbl_tip = QLabel("All network parameters operational. Zero active threats detected.")
        self.lbl_tip.setObjectName("TipLbl")
        
        vbox.addWidget(self.lbl_title)
        vbox.addWidget(self.lbl_value)
        vbox.addWidget(self.lbl_tip)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(14)
        
        layout.addLayout(vbox, stretch=1)
        layout.addWidget(self.progress_bar, stretch=2)
        
        self.setLayout(layout)
        self.update_score()

    def update_score(self):
        c = get_colors()
        score = 100
        
        # Deduct score ONLY for recent active alerts (last 1 hour)
        recent_alerts = db.get_recent_alerts(hours=1)
        critical_count = sum(1 for a in recent_alerts if a.get("severity") == "CRITICAL")
        high_count     = sum(1 for a in recent_alerts if a.get("severity") == "HIGH")
        
        score -= (critical_count * 25)
        score -= (high_count * 15)
        
        # Deduct score for active rogue/suspicious devices
        devices = db.get_devices()
        rogue_count = sum(1 for d in devices if "Rogue" in d.get("trust_status", "") or "Suspicious" in d.get("trust_status", ""))
        score -= (rogue_count * 10)
        
        score = max(0, min(100, score))
        
        if score >= 80:
            status_text = f"{score}% (EXCELLENT)"
            color_hex = c['success']
            tip = "Network parameter Status: Optimal. Zero active threats in the last hour."
        elif score >= 50:
            status_text = f"{score}% (WARNING)"
            color_hex = c['warning']
            tip = f"Attention Required: {rogue_count} Rogue/Suspicious devices or recent alerts detected. Review LAN Devices tab."
        else:
            status_text = f"{score}% (CRITICAL RISK)"
            color_hex = c['danger']
            tip = "CRITICAL SECURITY RISK: Active threat or anomaly detected! Inspect Threat Alerts log immediately."
            
        self.lbl_value.setText(status_text)
        self.lbl_value.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {color_hex};")
        self.lbl_tip.setText(f"💡 {tip}")
        self.progress_bar.setValue(score)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {c['border']};
                border-radius: 6px;
                background-color: {c['bg']};
            }}
            QProgressBar::chunk {{
                background-color: {color_hex};
                border-radius: 5px;
            }}
        """)

class DashboardTab(QWidget):
    alert_signal = pyqtSignal(dict)
    speed_signal = pyqtSignal(float, float)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.detector = None
        self.sniffer  = None
        self.analyzer = None
        self.speed    = None
        self.alert_count = 0
        self.talkers_map = defaultdict(int)  # ip -> packet count
        
        self._setup_ui()
        self.slow_refresh_timer = QTimer(self)
        self.slow_refresh_timer.setInterval(2000)
        self.slow_refresh_timer.timeout.connect(self._refresh_slow_widgets)
        self.slow_refresh_timer.start()
    
    def _setup_ui(self):
        c = get_colors()
        
        # 1. Top Security Gauge Meter
        self.gauge_widget = SecurityHealthScoreWidget(self)
        
        # 2. Metric Cards
        self.card_down   = StatCard("Download Speed", "0.0 KB/s", c['success'])
        self.card_up     = StatCard("Upload Speed",   "0.0 KB/s", c['warning'])
        self.card_pkts   = StatCard("Packet Rate",     "0 pkt/s", c['accent'])
        self.card_alerts = StatCard("Total Alerts",    "0",        c['danger'])
        
        cards = QGridLayout()
        cards.setSpacing(12)
        cards.addWidget(self.card_down,   0, 0)
        cards.addWidget(self.card_up,     0, 1)
        cards.addWidget(self.card_pkts,   0, 2)
        cards.addWidget(self.card_alerts, 0, 3)
        
        # 3. Live Chart & Top Bandwidth Talkers Table Side-by-Side
        self.chart = pg.PlotWidget()
        self.chart.setBackground(c['panel'])
        self.chart.setTitle("Live Network Traffic Stream (KB/s)", color=c['text'])
        self.chart.showGrid(x=True, y=True, alpha=0.2)
        self.chart.addLegend()
        self.down_data = deque([0]*60, maxlen=60)
        self.up_data   = deque([0]*60, maxlen=60)
        self.down_curve = self.chart.plot(pen=pg.mkPen(c['success'], width=2), name="Download")
        self.up_curve   = self.chart.plot(pen=pg.mkPen(c['warning'], width=2), name="Upload")
        
        # Top Talkers Table with Clean Proportional Columns
        self.table_talkers = QTableWidget(0, 3)
        self.table_talkers.setHorizontalHeaderLabels(["Device / IP", "Packets", "Share"])
        self.table_talkers.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_talkers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_talkers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_talkers.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_talkers.setMaximumWidth(420)
        
        chart_layout = QHBoxLayout()
        chart_layout.addWidget(self.chart, stretch=2)
        chart_layout.addWidget(self.table_talkers, stretch=1)

        # Action Buttons
        self.btn_start = QPushButton(" Start Monitoring")
        self.btn_start.setIcon(qta.icon('fa5s.play', color='white'))
        
        self.btn_stop  = QPushButton(" Stop")
        self.btn_stop.setIcon(qta.icon('fa5s.stop', color='white'))
        self.btn_stop.setEnabled(False)
        
        self.btn_start.clicked.connect(self.start_all)
        self.btn_stop.clicked.connect(self.stop_all)
        
        btns = QHBoxLayout()
        btns.addWidget(self.btn_start)
        btns.addWidget(self.btn_stop)
        btns.addStretch()
        
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(12)
        root.addWidget(self.gauge_widget)
        root.addLayout(cards)
        root.addLayout(chart_layout, stretch=1)
        root.addLayout(btns)
        self.setLayout(root)
        
        # Populate initial baseline talkers table
        self._update_talkers_table()
    
    def update_theme_styles(self):
        c = get_colors()
        self.chart.setBackground(c['panel'])
        self.chart.setTitle("Live Network Traffic Stream (KB/s)", color=c['text'])
        self.down_curve.setPen(pg.mkPen(c['success'], width=2))
        self.up_curve.setPen(pg.mkPen(c['warning'], width=2))
        
        self.card_down.apply_style(c['success'])
        self.card_up.apply_style(c['warning'])
        self.card_pkts.apply_style(c['accent'])
        self.card_alerts.apply_style(c['danger'])
        self.gauge_widget.update_score()

    def start_all(self):
        if not self.sniffer or not self.sniffer.isRunning():
            self.sniffer = SnifferThread()
            self.sniffer.error_occurred.connect(self._on_pipeline_error)
            self.sniffer.start()

        if not self.analyzer or not self.analyzer.isRunning():
            from core.packet_pipeline import PacketAnalyzerThread
            self.analyzer = PacketAnalyzerThread(self.sniffer.packet_queue, self.sniffer.dropped_count)
            self.analyzer.stats_ready.connect(self._on_pipeline_stats)
            self.analyzer.alert_signal.connect(self._on_alert)
            self.analyzer.error_occurred.connect(lambda msg: self._on_pipeline_error(msg))
            self.analyzer.start()
        
        if not self.speed or not self.speed.isRunning():
            self.speed = SpeedMonitorThread()
            self.speed.stats_updated.connect(self._update_speed)
            self.speed.start()
        
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
    
    def stop_all(self):
        self.slow_refresh_timer.stop()
        if self.sniffer:
            self.sniffer.stop()
        if self.analyzer:
            self.analyzer.stop()
        if self.speed:
            self.speed.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
    
    def _on_pipeline_stats(self, snapshot):
        self.talkers_map = defaultdict(int, snapshot.get("talkers", {}))
        self.card_pkts.set_value(f"{snapshot.get('rate', 0):,.0f} pkt/s")

    def _on_pipeline_error(self, message):
        self.card_pkts.set_value("Capture error")

    def _update_talkers_table(self):
        c = get_colors()
        self.table_talkers.setRowCount(0)
        
        devices = db.get_devices()
        dev_map = {d.get("ip"): (d.get("alias") or d.get("hostname") or d.get("device_type") or "Host") for d in devices}
        
        if not self.talkers_map:
            # Populate baseline active devices from database when sniffer packet map is starting
            if devices:
                for d in devices[:5]:
                    r = self.table_talkers.rowCount()
                    self.table_talkers.insertRow(r)
                    ip = d.get("ip", "192.168.1.1")
                    name = dev_map.get(ip, "Device")
                    self.table_talkers.setItem(r, 0, QTableWidgetItem(f"{ip} ({name[:12]})"))
                    self.table_talkers.setItem(r, 1, QTableWidgetItem("Active"))
                    self.table_talkers.setItem(r, 2, QTableWidgetItem("100%"))
            else:
                gw_ip = "192.168.8.1"
                r = self.table_talkers.rowCount()
                self.table_talkers.insertRow(r)
                self.table_talkers.setItem(r, 0, QTableWidgetItem(f"{gw_ip} (Gateway)"))
                self.table_talkers.setItem(r, 1, QTableWidgetItem("Active"))
                self.table_talkers.setItem(r, 2, QTableWidgetItem("100%"))
            return

        sorted_talkers = sorted(self.talkers_map.items(), key=lambda x: x[1], reverse=True)[:6]
        total_pkts = sum(self.talkers_map.values()) or 1
        
        for ip, count in sorted_talkers:
            pct = (count / total_pkts) * 100.0
            r = self.table_talkers.rowCount()
            self.table_talkers.insertRow(r)
            
            alias_str = dev_map.get(ip, "")
            display_name = f"{ip} ({alias_str[:12]})" if alias_str else ip
            
            self.table_talkers.setItem(r, 0, QTableWidgetItem(display_name))
            self.table_talkers.setItem(r, 1, QTableWidgetItem(f"{count:,}"))
            self.table_talkers.setItem(r, 2, QTableWidgetItem(f"{pct:.1f}%"))

    def _update_speed(self, down, up, pkts):
        self.card_down.set_value(f"{down:.1f} KB/s")
        self.card_up.set_value(f"{up:.1f} KB/s")
        self.card_pkts.set_value(f"{pkts} pkt/s")
        self.down_data.append(down)
        self.up_data.append(up)
        self.down_curve.setData(list(self.down_data))
        self.up_curve.setData(list(self.up_data))
        self.speed_signal.emit(down, up)

    def _refresh_slow_widgets(self):
        self._update_talkers_table()
        self.gauge_widget.update_score()

    def _on_alert(self, alert):
        self.alert_count += 1
        self.card_alerts.set_value(str(self.alert_count))
        self.alert_signal.emit(alert)
        self.gauge_widget.update_score()
