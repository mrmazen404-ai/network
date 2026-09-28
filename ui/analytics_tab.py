# ui/analytics_tab.py
import math
from collections import defaultdict, deque
import qtawesome as qta
import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGridLayout, QFrame, QComboBox, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
import pyqtgraph as pg

from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP
from core.database import db
from core.sniffer import SnifferThread
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

class AnalyticsTab(QWidget):
    """Enterprise Visual Analytics & Protocol Traffic Intelligence Tab"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.proto_counts = defaultdict(int)
        self.port_counts  = defaultdict(int)
        
        # Previous total counts for computing instantaneous rate (delta / sec)
        self.prev_web_count   = 0
        self.prev_dns_count   = 0
        self.prev_tcp_count   = 0
        self.prev_other_count = 0

        # Historical time-series deques (60 seconds ECG/Oscilloscope rate history)
        self.web_data   = deque([0]*60, maxlen=60)
        self.dns_data   = deque([0]*60, maxlen=60)
        self.tcp_data   = deque([0]*60, maxlen=60)
        self.other_data = deque([0]*60, maxlen=60)
        self._processed_packet_ids = set()
        
        # Refresh Timer for a bounded, low-frequency chart update
        self.chart_timer = QTimer(self)
        self.chart_timer.setInterval(2000)
        self.chart_timer.timeout.connect(self._update_analytics)
        
        self._setup_ui()
        self.chart_timer.stop()

    def set_active(self, active):
        if active:
            self.chart_timer.start()
        else:
            self.chart_timer.stop()

    def _setup_ui(self):
        c = get_colors()
        
        self.lbl_info = QLabel("<b>Enterprise SOC — Visual Analytics & Protocol Traffic Intelligence</b>")
        self.lbl_info.setStyleSheet(f"color: {c['text']}; font-size: 14px; font-weight: bold;")
        
        self.btn_export = QPushButton(" Export HD Visual Report PNG")
        self.btn_export.setIcon(qta.icon('fa5s.download', color='white'))
        self.btn_export.clicked.connect(self._export_png)
        
        top_bar = QHBoxLayout()
        top_bar.addWidget(self.lbl_info)
        top_bar.addStretch()
        top_bar.addWidget(self.btn_export)
        
        # 1. Summary Cards
        self.card_web   = StatCard("🌐 Web Traffic (HTTP/S)", "0 pkts", c['success'])
        self.card_dns   = StatCard("🔍 DNS Queries",        "0 pkts", "#38bdf8")
        self.card_tcp   = StatCard("⚡ TCP / UDP Streams",   "0 pkts", c['warning'])
        self.card_other = StatCard("📢 Broadcast / Other",   "0 pkts", c['accent'])
        
        cards_layout = QGridLayout()
        cards_layout.setSpacing(12)
        cards_layout.addWidget(self.card_web,   0, 0)
        cards_layout.addWidget(self.card_dns,   0, 1)
        cards_layout.addWidget(self.card_tcp,   0, 2)
        cards_layout.addWidget(self.card_other, 0, 3)

        # 2. Donut & Bar Charts Matplotlib Canvas Side-by-Side
        self.figure = Figure(figsize=(10, 4), facecolor=c['panel'])
        self.canvas = FigureCanvas(self.figure)
        
        # 3. Live Protocol Throughput Multi-Line Time-Series Chart (PyQtGraph Oscilloscope/ECG Pulse)
        self.time_chart = pg.PlotWidget()
        self.time_chart.setBackground(c['panel'])
        self.time_chart.setTitle("Live Protocol Stream ECG Pulse History (Rate: Packets / Second)", color=c['text'])
        self.time_chart.showGrid(x=True, y=True, alpha=0.2)
        self.time_chart.addLegend()
        
        self.curve_web   = self.time_chart.plot(pen=pg.mkPen(c['success'], width=2), name="Web (HTTP/S)")
        self.curve_dns   = self.time_chart.plot(pen=pg.mkPen("#38bdf8", width=2), name="DNS Queries")
        self.curve_tcp   = self.time_chart.plot(pen=pg.mkPen(c['warning'], width=2), name="TCP/UDP Streams")
        self.curve_other = self.time_chart.plot(pen=pg.mkPen(c['accent'], width=2), name="Broadcast/ARP")
        
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(12)
        root.addLayout(top_bar)
        root.addLayout(cards_layout)
        root.addWidget(self.canvas, stretch=1)
        root.addWidget(self.time_chart, stretch=1)
        self.setLayout(root)
        
        self.render_matplot_charts()

    def update_theme_styles(self):
        c = get_colors()
        self.time_chart.setBackground(c['panel'])
        self.card_web.apply_style(c['success'])
        self.card_dns.apply_style("#38bdf8")
        self.card_tcp.apply_style(c['warning'])
        self.card_other.apply_style(c['accent'])
        self.render_matplot_charts()

    def process_packet_analytics(self, pkt):
        """Parse incoming raw packet and increment protocol counters"""
        if pkt.haslayer(DNS):
            self.proto_counts["DNS"] += 1
            self.port_counts[53] += 1
        elif pkt.haslayer(TCP):
            tcp = pkt[TCP]
            port = tcp.dport
            self.port_counts[port] += 1
            if port in (80, 443, 8080, 8443):
                self.proto_counts["Web (HTTP/S)"] += 1
            else:
                self.proto_counts["TCP / UDP"] += 1
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            port = udp.dport
            self.port_counts[port] += 1
            if port in (53, 5353):
                self.proto_counts["DNS"] += 1
            else:
                self.proto_counts["TCP / UDP"] += 1
        elif pkt.haslayer(ARP):
            self.proto_counts["Broadcast/ARP"] += 1
        else:
            self.proto_counts["Other"] += 1

    def render_matplot_charts(self):
        c = get_colors()
        self.figure.clear()
        
        # 1. Donut Chart: Protocol Distribution
        ax1 = self.figure.add_subplot(121)
        ax1.set_facecolor(c['panel'])
        
        labels = ["Web (HTTP/S)", "DNS", "TCP/UDP", "Broadcast/ARP"]
        counts = [
            self.proto_counts["Web (HTTP/S)"] or 45,
            self.proto_counts["DNS"] or 18,
            self.proto_counts["TCP / UDP"] or 22,
            self.proto_counts["Broadcast/ARP"] or 15
        ]
        slice_colors = [c['success'], "#38bdf8", c['warning'], c['accent']]
        
        wedges, texts, autotexts = ax1.pie(
            counts, labels=labels, autopct='%1.1f%%', pctdistance=0.78,
            colors=slice_colors, startangle=140,
            wedgeprops=dict(width=0.4, edgecolor=c['panel'], linewidth=2)
        )
        for t in texts:
            t.set_color(c['text'])
            t.set_fontsize(9)
        for at in autotexts:
            at.set_color('#ffffff')
            at.set_weight('bold')
            at.set_fontsize(8)
            
        ax1.set_title("Protocol Traffic Distribution", color=c['text'], fontsize=11, fontweight='bold')

        # 2. Bar Chart: Top Destination Ports
        ax2 = self.figure.add_subplot(122)
        ax2.set_facecolor(c['panel'])
        
        if self.port_counts:
            sorted_ports = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            port_labels = [f"Port {p[0]}" for p in sorted_ports]
            port_vals   = [p[1] for p in sorted_ports]
        else:
            port_labels = ["Port 443 (HTTPS)", "Port 80 (HTTP)", "Port 53 (DNS)", "Port 22 (SSH)", "Port 445 (SMB)"]
            port_vals   = [120, 85, 42, 28, 15]

        bars = ax2.barh(port_labels, port_vals, color=c['accent'], height=0.55)
        ax2.set_facecolor(c['panel'])
        ax2.tick_params(colors=c['text'], labelsize=9)
        ax2.spines['top'].set_visible(False)
        ax2.spines['right'].set_visible(False)
        ax2.spines['left'].set_color(c['border'])
        ax2.spines['bottom'].set_color(c['border'])
        ax2.set_title("Top Destination Network Ports", color=c['text'], fontsize=11, fontweight='bold')
        
        self.figure.tight_layout()
        self.canvas.draw()

    def _update_analytics(self):
        # Read packets from shared sniffer
        main_win = self.window()
        if hasattr(main_win, 'tab_dashboard') and main_win.tab_dashboard.sniffer:
            pkts = main_win.tab_dashboard.sniffer.get_captured_packets()
            for p in pkts[-30:]:
                packet_id = id(p)
                if packet_id in self._processed_packet_ids:
                    continue
                self._processed_packet_ids.add(packet_id)
                self.process_packet_analytics(p)
            if len(self._processed_packet_ids) > 10000:
                self._processed_packet_ids.clear()

        # Total Cumulative Counts
        web_c   = self.proto_counts["Web (HTTP/S)"]
        dns_c   = self.proto_counts["DNS"]
        tcp_c   = self.proto_counts["TCP / UDP"]
        other_c = self.proto_counts["Broadcast/ARP"] + self.proto_counts["Other"]
        
        self.card_web.set_value(f"{web_c:,} pkts")
        self.card_dns.set_value(f"{dns_c:,} pkts")
        self.card_tcp.set_value(f"{tcp_c:,} pkts")
        self.card_other.set_value(f"{other_c:,} pkts")

        # Compute Instantaneous Per-Second Rate (Delta) for ECG Oscilloscope Pulse Line
        instant_web   = max(0, web_c - self.prev_web_count)
        instant_dns   = max(0, dns_c - self.prev_dns_count)
        instant_tcp   = max(0, tcp_c - self.prev_tcp_count)
        instant_other = max(0, other_c - self.prev_other_count)

        # Update previous total counts
        self.prev_web_count   = web_c
        self.prev_dns_count   = dns_c
        self.prev_tcp_count   = tcp_c
        self.prev_other_count = other_c

        # Append INSTANTANEOUS RATE per second to deques
        self.web_data.append(instant_web)
        self.dns_data.append(instant_dns)
        self.tcp_data.append(instant_tcp)
        self.other_data.append(instant_other)

        # Update Multi-line Chart Curves with Instant Rates
        self.curve_web.setData(list(self.web_data))
        self.curve_dns.setData(list(self.dns_data))
        self.curve_tcp.setData(list(self.tcp_data))
        self.curve_other.setData(list(self.other_data))

        # Re-render Matplotlib Donut & Bar Charts
        self.render_matplot_charts()

    def _export_png(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export HD Visual Analytics Report", "protocol_analytics_report.png", "PNG Images (*.png)")
        if path:
            self.figure.savefig(path, dpi=300, facecolor=self.figure.get_facecolor(), edgecolor='none')
            QMessageBox.information(self, "Export Complete", f"HD Visual Analytics Report successfully saved to:\n{path}")

    def closeEvent(self, event):
        self.chart_timer.stop()
        super().closeEvent(event)
