# ui/packets_tab.py
import time
from collections import deque
import qtawesome as qta

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel, QLineEdit, QComboBox, QSplitter, QTreeWidget,
    QTreeWidgetItem, QPlainTextEdit, QHeaderView, QFrame
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor, QBrush

from scapy.all import IP, TCP, UDP, ARP, ICMP, DNS, Raw
from core.sniffer import SnifferThread
from config import get_colors

def eval_packet_threat_color(pkt, proto, dpi_info, c):
    """
    Wireshark-Grade Security Color Coding:
    - Critical Danger (Neon Red): SYN Flood, ARP Spoofing, Port Scan, Insecure Ports (Telnet/FTP/SMB)
    - Suspicious Warning (Neon Yellow/Orange): ICMP Flood, TCP RST/FIN Storms
    - Safe Web / DNS (Cyan / Green): DNS Queries, HTTP/HTTPS Streams
    - Normal (Default theme text color)
    """
    text_info = f"{proto} {dpi_info}".lower()
    
    # 1. Critical Danger Packets (Neon Red Foreground + Translucent Red BG)
    if any(k in text_info for k in ["spoofing", "flood", "syn flood", "port scan"]):
        return QColor(c['danger']), QColor(180, 20, 20, 70)
        
    # Check for insecure/vulnerable legacy ports (Telnet 23, FTP 21, SMB 445)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.dport in (21, 23, 445, 139) or tcp.sport in (21, 23, 445, 139):
            return QColor("#ff8800"), QColor(100, 50, 0, 50)  # Orange warning for insecure cleartext ports

    # 2. Suspicious / Warning Packets (Neon Yellow)
    if any(k in text_info for k in ["icmp", "rst", "invalid", "refused"]):
        return QColor(c['warning']), QColor(80, 80, 0, 40)

    # 3. DNS & Web Traffic (Cyan / Green)
    if proto == "DNS" or "dns" in text_info:
        return QColor("#38bdf8"), None
    if proto == "HTTP" or "http" in text_info or "tls" in text_info:
        return QColor(c['success']), None
        
    return QColor(c['text']), None

def extract_packet_dpi_info(pkt):
    """Enterprise Feature: Deep Packet Inspection (DPI) Info Extractor"""
    try:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            op = "Request" if arp.op == 1 else "Reply"
            return f"ARP {op}: {arp.psrc} -> {arp.pdst}"
            
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:
                qname = dns.qd.qname.decode("utf-8", "replace").rstrip(".")
                return f"DNS Query: {qname}"
            elif dns.an:
                return f"DNS Response: {len(dns.an)} answer records"

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            flag_str = ",".join(flags) if flags else "Data"
            
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode("utf-8", "replace")
                    if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                        first_line = payload.splitlines()[0]
                        return f"HTTP: {first_line[:40]}"
                except Exception:
                    pass
            return f"TCP {tcp.sport} -> {tcp.dport} [{flag_str}]"

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            return f"UDP {udp.sport} -> {udp.dport}"

        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            return f"ICMP Type {icmp.type} Code {icmp.code}"

        if pkt.haslayer(IP):
            ip = pkt[IP]
            return f"IP {ip.src} -> {ip.dst} (Proto {ip.proto})"

        return "Raw Ethernet Frame"
    except Exception as e:
        return f"Packet ({len(pkt)} bytes)"

def format_hex_dump(raw_bytes):
    """Format raw packet bytes into traditional Wireshark Hex/ASCII Dump"""
    if not raw_bytes:
        return "No Raw Payload Bytes Available"
        
    lines = []
    length = len(raw_bytes)
    for i in range(0, length, 16):
        chunk = raw_bytes[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        hex_str = f"{hex_str:<48}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_str}  {ascii_str}")
    return "\n".join(lines)

class PacketsTab(QWidget):
    MAX_ROWS = 1000
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.sniffer = None
        self.counter = 0
        self.buffer_queue = deque(maxlen=5000)
        self.packet_store = {}  # packet_id -> raw scapy pkt
        
        # Batch timer for smooth UI rendering
        self.flush_timer = QTimer(self)
        self.flush_timer.setInterval(250)  # Bounded UI refresh under load
        self.flush_timer.timeout.connect(self._flush_buffer)
        
        self._setup_ui()
    
    def _setup_ui(self):
        c = get_colors()
        
        # 1. Top Controls Toolbar
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(" Filter BPF / Keyword Search (e.g. 192.168.8.105, DNS, HTTP)...")
        
        self.combo_proto = QComboBox()
        self.combo_proto.addItems([
            "All Real Traffic (Hide ARP Scans)",
            "🌐 DNS & Web Traffic Only",
            "⚡ TCP & UDP Streams Only",
            "📢 Multicast & Discovery Only",
            "Raw All Packets (Including ARP Scans)"
        ])
        
        self.btn_start = QPushButton(" Sniff")
        self.btn_start.setIcon(qta.icon('fa5s.play', color='white'))
        
        self.btn_stop  = QPushButton(" Stop")
        self.btn_stop.setIcon(qta.icon('fa5s.stop', color='white'))
        self.btn_stop.setEnabled(False)
        
        self.btn_clear = QPushButton(" Clear Stream")
        self.btn_clear.setIcon(qta.icon('fa5s.trash-alt', color='white'))
        
        self.btn_start.clicked.connect(self.start)
        self.btn_stop.clicked.connect(self.stop)
        self.btn_clear.clicked.connect(self.clear)
        
        self.lbl_count = QLabel("0 Packets")
        self.lbl_count.setStyleSheet(f"font-weight: bold; color: {c['accent']};")
        
        top_bar = QHBoxLayout()
        top_bar.addWidget(self.filter_input, stretch=2)
        top_bar.addWidget(self.combo_proto)
        top_bar.addWidget(self.btn_start)
        top_bar.addWidget(self.btn_stop)
        top_bar.addWidget(self.btn_clear)
        top_bar.addWidget(self.lbl_count)
        
        # 2. Main Packet Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["#", "Timestamp", "Source IP", "Destination IP", "Protocol", "Size", "Info / Payload Details (DPI)"])
        self.table.verticalHeader().setVisible(False)  # Hide duplicate vertical row index
        
        # Set Proportional Column Widths
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(3, 130)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        
        # 3. Bottom Wireshark Packet Inspector (Splitter Pane)
        self.inspector_tree = QTreeWidget()
        self.inspector_tree.setHeaderLabels(["Packet Header Layers (Tree View)", "Value / Details"])
        self.inspector_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 9.5))
        self.hex_view.setStyleSheet(f"background-color: #0a0e14; color: #00ff88; border: none; padding: 6px;")
        
        inspector_splitter = QSplitter(Qt.Horizontal)
        inspector_splitter.addWidget(self.inspector_tree)
        inspector_splitter.addWidget(self.hex_view)
        inspector_splitter.setSizes([350, 450])
        
        inspector_frame = QFrame()
        inspector_frame.setStyleSheet(f"background-color: {c['panel']}; border: 1px solid {c['border']}; border-radius: 6px; padding: 6px;")
        vbox_insp = QVBoxLayout()
        vbox_insp.setContentsMargins(6, 4, 6, 4)
        vbox_insp.addWidget(QLabel("<b>🔍 Interactive Wireshark Packet Inspector (Layers & Hex/ASCII Dump)</b>"))
        vbox_insp.addWidget(inspector_splitter)
        inspector_frame.setLayout(vbox_insp)

        # Main Vertical Splitter Pane
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.table)
        main_splitter.addWidget(inspector_frame)
        main_splitter.setSizes([420, 220])
        
        root = QVBoxLayout()
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)
        root.addLayout(top_bar)
        root.addWidget(main_splitter)
        self.setLayout(root)
    
    def set_shared_sniffer(self, sniffer):
        if self.sniffer and self.sniffer != sniffer:
            try:
                self.sniffer.packet_batch.disconnect(self._on_packet_batch)
            except Exception:
                pass
        self.sniffer = sniffer
        if self.sniffer:
            self.sniffer.packet_batch.connect(self._on_packet_batch)

    def _on_packet_batch(self, packets):
        # A bounded batch keeps the UI event queue finite under high traffic.
        for packet in packets:
            self._on_packet(packet)

    def start(self):
        self.buffer_queue.clear()
        
        main_win = self.window()
        if hasattr(main_win, 'tab_dashboard') and main_win.tab_dashboard.sniffer:
            self.set_shared_sniffer(main_win.tab_dashboard.sniffer)
            if not self.sniffer.isRunning():
                main_win.tab_dashboard.start_all()
        else:
            if not hasattr(self, '_local_sniffer') or not self._local_sniffer:
                from core.sniffer import SnifferThread
                self._local_sniffer = SnifferThread()
            self.set_shared_sniffer(self._local_sniffer)
            if not self.sniffer.isRunning():
                self.sniffer.start()
                
        self.flush_timer.start()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
    
    def stop(self):
        self.flush_timer.stop()
        self._flush_buffer()
        if hasattr(self, '_local_sniffer') and self._local_sniffer and self._local_sniffer == self.sniffer:
            self._local_sniffer.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
    
    def clear(self):
        self.buffer_queue.clear()
        self.packet_store.clear()
        self.table.setRowCount(0)
        self.inspector_tree.clear()
        self.hex_view.clear()
        self.counter = 0
        self.lbl_count.setText("0 Packets")
    
    def _on_packet(self, pkt):
        src = dst = proto = "-"
        size = len(pkt)
        
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        elif pkt.haslayer(DNS):
            proto = "DNS"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            
        dpi_info = extract_packet_dpi_info(pkt)
        proto_filter = self.combo_proto.currentText()
        
        # 1. Filter out repetitive self-generated ARP subnet scan storm packets
        if "Hide ARP Scans" in proto_filter and pkt.haslayer(ARP):
            if pkt[ARP].op == 1 and "Request" in dpi_info: # Hide ARP scan sweeps
                return

        # 2. Protocol Category Filter
        if "DNS & Web" in proto_filter and proto not in ("DNS", "HTTP", "HTTPS") and "DNS" not in dpi_info and "HTTP" not in dpi_info:
            return
        if "TCP & UDP Streams" in proto_filter and proto not in ("TCP", "UDP"):
            return
        if "Multicast & Discovery" in proto_filter and proto not in ("mDNS", "SSDP", "DHCP", "ARP"):
            return

        # 3. Keyword / BPF Search Filter
        f = self.filter_input.text().strip().lower()
        if f and f not in f"{src} {dst} {proto} {dpi_info}".lower():
            return
            
        self.counter += 1
        self.packet_store[self.counter] = pkt
        if len(self.packet_store) > self.MAX_ROWS * 2:
            oldest = sorted(self.packet_store)[:self.MAX_ROWS]
            for packet_id in oldest:
                self.packet_store.pop(packet_id, None)
        self.buffer_queue.append((self.counter, time.strftime("%H:%M:%S"), src, dst, proto, f"{size} B", dpi_info, pkt))

    def _flush_buffer(self):
        c = get_colors()
        if not self.buffer_queue:
            return
        
        batch_size = min(len(self.buffer_queue), 100)
        for _ in range(batch_size):
            num, ts, src, dst, proto, size, dpi_info, raw_pkt = self.buffer_queue.popleft()
            
            if self.table.rowCount() >= self.MAX_ROWS:
                self.table.removeRow(0)
            
            r = self.table.rowCount()
            self.table.insertRow(r)
            
            # Security Threat Color Evaluation
            fg_color, bg_color = eval_packet_threat_color(raw_pkt, proto, dpi_info, c)
            
            it_num = QTableWidgetItem(str(num))
            it_num.setData(Qt.UserRole, num)
            
            items = [
                it_num,
                QTableWidgetItem(ts),
                QTableWidgetItem(src),
                QTableWidgetItem(dst),
                QTableWidgetItem(proto),
                QTableWidgetItem(size),
                QTableWidgetItem(dpi_info)
            ]
            
            for col_idx, item in enumerate(items):
                if fg_color:
                    item.setForeground(fg_color)
                if bg_color:
                    item.setBackground(QBrush(bg_color))
                self.table.setItem(r, col_idx, item)
        
        self.table.scrollToBottom()
        self.lbl_count.setText(f"{self.counter} Packets")

    def _on_row_selected(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        item_0 = self.table.item(row, 0)
        pkt_num = item_0.data(Qt.UserRole) if item_0 else None
        
        if not pkt_num or pkt_num not in self.packet_store:
            return
            
        pkt = self.packet_store[pkt_num]
        self._inspect_packet(pkt, pkt_num)

    def _inspect_packet(self, pkt, pkt_num):
        c = get_colors()
        self.inspector_tree.clear()
        
        # 1. Layer 1: Frame Summary
        root_frame = QTreeWidgetItem(["Frame Summary", f"Frame #{pkt_num}: {len(pkt)} bytes on wire"])
        self.inspector_tree.addTopLevelItem(root_frame)
        
        # 2. Layer 2: Ethernet Layer
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            item_arp = QTreeWidgetItem(["ARP Header", f"Op: {'Request' if arp.op==1 else 'Reply'}"])
            item_arp.addChild(QTreeWidgetItem(["Sender Hardware (MAC)", arp.hwsrc]))
            item_arp.addChild(QTreeWidgetItem(["Sender Protocol (IP)", arp.psrc]))
            item_arp.addChild(QTreeWidgetItem(["Target Hardware (MAC)", arp.hwdst]))
            item_arp.addChild(QTreeWidgetItem(["Target Protocol (IP)", arp.pdst]))
            self.inspector_tree.addTopLevelItem(item_arp)

        # 3. Layer 3: IPv4 Layer
        if pkt.haslayer(IP):
            ip = pkt[IP]
            item_ip = QTreeWidgetItem(["Internet Protocol (IPv4)", f"Src: {ip.src} -> Dst: {ip.dst}"])
            item_ip.addChild(QTreeWidgetItem(["Version", str(ip.version)]))
            item_ip.addChild(QTreeWidgetItem(["Header Length", f"{ip.ihl * 4} bytes"]))
            item_ip.addChild(QTreeWidgetItem(["Time to Live (TTL)", str(ip.ttl)]))
            item_ip.addChild(QTreeWidgetItem(["Protocol", f"{ip.proto}"]))
            item_ip.addChild(QTreeWidgetItem(["Header Checksum", hex(ip.chksum)]))
            self.inspector_tree.addTopLevelItem(item_ip)

        # 4. Layer 4: TCP / UDP Layer
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            item_tcp = QTreeWidgetItem(["Transmission Control Protocol (TCP)", f"Port {tcp.sport} -> {tcp.dport}"])
            item_tcp.addChild(QTreeWidgetItem(["Source Port", str(tcp.sport)]))
            item_tcp.addChild(QTreeWidgetItem(["Destination Port", str(tcp.dport)]))
            item_tcp.addChild(QTreeWidgetItem(["Sequence Number", str(tcp.seq)]))
            item_tcp.addChild(QTreeWidgetItem(["Acknowledgment Number", str(tcp.ack)]))
            item_tcp.addChild(QTreeWidgetItem(["Flags", str(tcp.flags)]))
            item_tcp.addChild(QTreeWidgetItem(["Window Size", str(tcp.window)]))
            self.inspector_tree.addTopLevelItem(item_tcp)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            item_udp = QTreeWidgetItem(["User Datagram Protocol (UDP)", f"Port {udp.sport} -> {udp.dport}"])
            item_udp.addChild(QTreeWidgetItem(["Source Port", str(udp.sport)]))
            item_udp.addChild(QTreeWidgetItem(["Destination Port", str(udp.dport)]))
            item_udp.addChild(QTreeWidgetItem(["Length", f"{udp.len} bytes"]))
            item_udp.addChild(QTreeWidgetItem(["Checksum", hex(udp.chksum)]))
            self.inspector_tree.addTopLevelItem(item_udp)

        self.inspector_tree.expandAll()

        # 5. Populate Hex/ASCII Raw Dump
        try:
            raw_bytes = bytes(pkt)
            self.hex_view.setPlainText(format_hex_dump(raw_bytes))
        except Exception:
            self.hex_view.setPlainText("Failed to render raw packet hex dump.")
