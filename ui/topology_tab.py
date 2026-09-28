# ui/topology_tab.py
import math
import socket
import qtawesome as qta
import networkx as nx

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox,
    QFileDialog, QMessageBox, QFrame, QGraphicsView, QGraphicsScene,
    QGraphicsItem, QGraphicsItemGroup, QGraphicsLineItem, QGraphicsEllipseItem,
    QGraphicsPixmapItem, QGraphicsTextItem, QGraphicsDropShadowEffect, QMenu
)
from PySide6.QtCore import Qt, QTimer, QRectF, QPointF
from PySide6.QtGui import QColor, QPen, QBrush, QFont, QPainter, QImage, QPixmap, QAction, QPainterPath

from core.database import db
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

class RadarRingItem(QGraphicsEllipseItem):
    """Animated Expanding Radar Wave Ring around the Core Gateway Node"""
    def __init__(self, color_hex="#00e5ff", parent=None):
        super().__init__(-60, -60, 120, 120, parent)
        self.radius = 60.0
        self.max_radius = 160.0
        self.color_hex = color_hex
        self.setZValue(2)
        self.update_graphics()

    def advance_wave(self):
        self.radius += 1.5
        if self.radius > self.max_radius:
            self.radius = 60.0
        self.update_graphics()

    def update_graphics(self):
        self.setRect(-self.radius, -self.radius, self.radius * 2, self.radius * 2)
        alpha = int(255 * (1.0 - (self.radius / self.max_radius)))
        c = QColor(self.color_hex)
        c.setAlpha(max(0, min(255, alpha)))
        self.setPen(QPen(c, 2, Qt.DashLine))
        self.setBrush(QBrush(Qt.NoBrush))

class PulseParticleItem(QGraphicsEllipseItem):
    """Animated packet particle traveling along network connection links"""
    def __init__(self, start_pos, end_pos, color_hex="#00e5ff", parent=None):
        super().__init__(-6, -6, 12, 12, parent)
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.progress = 0.0
        self.speed = 0.016
        
        c = QColor(color_hex)
        self.setBrush(QBrush(c))
        self.setPen(QPen(QColor("#ffffff"), 1))
        self.setZValue(5)
        self.update_position()

    def advance_pulse(self):
        self.progress += self.speed
        if self.progress > 1.0:
            self.progress = 0.0
        self.update_position()

    def update_position(self):
        x = self.start_pos.x() + (self.end_pos.x() - self.start_pos.x()) * self.progress
        y = self.start_pos.y() + (self.end_pos.y() - self.start_pos.y()) * self.progress
        self.setPos(x, y)

class NodeGraphicsItem(QGraphicsItemGroup):
    """Interactive Custom Rendered Device Node with Vector Graphics & Glowing Badges"""
    def __init__(self, node_id, ip, name, device_type, trust_status, is_gateway=False, parent=None):
        super().__init__(parent)
        self.node_id = node_id
        self.ip = ip
        self.name = name
        self.device_type = device_type
        self.trust_status = trust_status
        self.is_gateway = is_gateway
        
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)
        
        self._build_graphics()

    def _build_graphics(self):
        c = get_colors()
        
        if self.is_gateway:
            border_color = QColor(c['accent'])
            icon_name = "fa5s.broadcast-tower"
            node_size = 68
        elif "Rogue" in self.trust_status or "Suspicious" in self.trust_status:
            border_color = QColor(c['danger'])
            icon_name = "fa5s.exclamation-triangle"
            node_size = 56
        elif "Mobile" in self.device_type or "Apple" in self.device_type or "Android" in self.device_type or "Smartphone" in self.device_type:
            border_color = QColor("#38bdf8")
            icon_name = "fa5s.mobile-alt"
            node_size = 54
        elif "Printer" in self.device_type:
            border_color = QColor("#a855f7")
            icon_name = "fa5s.print"
            node_size = 54
        elif "Trusted" in self.trust_status:
            border_color = QColor(c['success'])
            icon_name = "fa5s.desktop"
            node_size = 54
        else:
            border_color = QColor(c['text_sub'])
            icon_name = "fa5s.server"
            node_size = 54

        # 1. Outer Outer Halo Ring
        halo_ring = QGraphicsEllipseItem(-node_size/2 - 6, -node_size/2 - 6, node_size + 12, node_size + 12)
        halo_color = QColor(border_color)
        halo_color.setAlpha(60)
        halo_ring.setBrush(QBrush(Qt.NoBrush))
        halo_ring.setPen(QPen(halo_color, 2, Qt.DashLine))
        self.addToGroup(halo_ring)

        # 2. Main Node Circle
        bg_circle = QGraphicsEllipseItem(-node_size/2, -node_size/2, node_size, node_size)
        bg_circle.setBrush(QBrush(QColor(c['panel'])))
        bg_circle.setPen(QPen(border_color, 3, Qt.SolidLine))
        self.addToGroup(bg_circle)

        # 3. Vector Device Icon
        icon_pixmap = qta.icon(icon_name, color=border_color.name()).pixmap(30, 30)
        pix_item = QGraphicsPixmapItem(icon_pixmap)
        pix_item.setPos(-15, -15)
        self.addToGroup(pix_item)

        # 4. Label Text Badge
        clean_name = self.name.replace('💻', '').replace('📱', '').replace('🖨️', '').replace('🌐', '').replace('📺', '').replace('⚠️', '').strip()
        lbl_text = QGraphicsTextItem(f"{clean_name}\n({self.ip})")
        lbl_text.setDefaultTextColor(QColor(c['text']))
        lbl_text.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_text.setPos(-45, node_size/2 + 4)
        self.addToGroup(lbl_text)

class TopologyTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.particles = []
        self.radar_waves = []
        self.node_items = {}
        self._active = False
        
        # 50 FPS Pulse Timer for network traffic particles & radar waves
        self.pulse_timer = QTimer(self)
        self.pulse_timer.setInterval(20)  # ~50 FPS
        self.pulse_timer.timeout.connect(self._advance_animation)
        
        self._setup_ui()

    def _setup_ui(self):
        c = get_colors()
        
        self.lbl_info = QLabel("<b>Enterprise SOC — Live Animated Topology Matrix & Radar Wave</b>")
        self.lbl_info.setStyleSheet(f"color: {c['text']}; font-size: 14px; font-weight: bold;")
        
        self.combo_layout = QComboBox()
        self.combo_layout.addItems([
            "Radial Gateway Star Layout",
            "Force-Directed Spring Network",
            "Circular Ring Topology"
        ])
        self.combo_layout.currentTextChanged.connect(self.render_graph)
        
        self.combo_filter = QComboBox()
        self.combo_filter.addItems(["All Active Nodes", "Trusted Nodes Only", "Rogue & Threats Only"])
        self.combo_filter.currentTextChanged.connect(self.render_graph)
        
        self.btn_zoom_in = QPushButton("+")
        self.btn_zoom_in.setFixedWidth(30)
        self.btn_zoom_in.clicked.connect(lambda: self.view.scale(1.2, 1.2))
        
        self.btn_zoom_out = QPushButton("-")
        self.btn_zoom_out.setFixedWidth(30)
        self.btn_zoom_out.clicked.connect(lambda: self.view.scale(0.8, 0.8))
        
        self.btn_refresh = QPushButton(" Refresh Matrix")
        self.btn_refresh.setIcon(qta.icon('fa5s.sync-alt', color='white'))
        self.btn_refresh.clicked.connect(self.render_graph)
        
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.lbl_info)
        top_layout.addStretch()
        top_layout.addWidget(QLabel("Layout:"))
        top_layout.addWidget(self.combo_layout)
        top_layout.addWidget(QLabel("Filter:"))
        top_layout.addWidget(self.combo_filter)
        top_layout.addWidget(self.btn_zoom_in)
        top_layout.addWidget(self.btn_zoom_out)
        top_layout.addWidget(self.btn_refresh)
        
        # Legend Panel
        legend_frame = QFrame()
        legend_frame.setStyleSheet(f"background-color: {c['panel_hover']}; border-radius: 8px; padding: 6px; border: 1px solid {c['border']};")
        legend_layout = QHBoxLayout()
        legend_layout.setContentsMargins(10, 4, 10, 4)
        
        legend_items = [
            ("📡 Core Gateway (Radar Ring)", c['accent']),
            ("💻 Workstation / PC", c['success']),
            ("📱 Smartphone / Mobile", "#38bdf8"),
            ("🖨️ Printer", "#a855f7"),
            ("⚠️ Rogue Threat", c['danger'])
        ]
        for text, color in legend_items:
            lbl = QLabel(text)
            lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")
            legend_layout.addWidget(lbl)
        legend_frame.setLayout(legend_layout)

        # Hardware-Accelerated QGraphicsView Scene
        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        self.view.setStyleSheet(f"QGraphicsView {{ background-color: {c['bg']}; border: 1px solid {c['border']}; border-radius: 8px; }}")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        layout.addLayout(top_layout)
        layout.addWidget(legend_frame)
        layout.addWidget(self.view, stretch=1)
        self.setLayout(layout)
        
        self.render_graph()

    def render_graph(self):
        c = get_colors()
        self.pulse_timer.stop()
        self.scene.clear()
        self.particles.clear()
        self.radar_waves.clear()
        self.node_items.clear()
        
        gw_ip = get_default_gateway_ip()
        G = nx.Graph()
        
        router_node = f"Enterprise Gateway\n[{gw_ip}]"
        G.add_node(router_node, type="router", trust="Trusted", ip=gw_ip, is_gw=True)
        
        devices = db.get_devices()
        filter_mode = self.combo_filter.currentText()
        
        if devices:
            for d in devices:
                ip = d.get("ip", "")
                if ip == gw_ip:
                    continue
                trust = d.get("trust_status", "Unknown")
                if "Trusted Only" in filter_mode and "Trusted" not in trust:
                    continue
                if "Rogue Only" in filter_mode and "Rogue" not in trust and "Suspicious" not in trust:
                    continue
                
                dev_type = d.get("device_type", "Host")
                alias = d.get("alias", "")
                hostname = d.get("hostname", "")
                name = alias or hostname or "Host"
                
                G.add_node(ip, name=name, ip=ip, type=dev_type, trust=trust, is_gw=False)
                G.add_edge(router_node, ip)
        else:
            empty_item = self.scene.addText("No observed devices yet. Run a LAN scan to populate the topology.")
            empty_item.setDefaultTextColor(QColor(c['text_sub']))
            empty_item.setPos(-180, 90)

        # Layout Positions
        pos = {}
        nodes_list = list(G.nodes())
        if nodes_list:
            pos[router_node] = QPointF(0, 0)
            children = [n for n in nodes_list if n != router_node]
            n_children = len(children)
            radius = 290
            for idx, child in enumerate(children):
                angle = (idx / max(1, n_children)) * 2 * math.pi
                x = radius * math.cos(angle)
                y = radius * math.sin(angle)
                pos[child] = QPointF(x, y)

        # 1. Add Animated Radar Wave Ring on Gateway Router Node
        gw_pos = pos.get(router_node, QPointF(0, 0))
        radar_wave = RadarRingItem(color_hex=c['accent'])
        radar_wave.setPos(gw_pos.x(), gw_pos.y())
        self.scene.addItem(radar_wave)
        self.radar_waves.append(radar_wave)

        # 2. Draw Animated Connection Links & Pulse Particles
        for child_node, child_pos in pos.items():
            if child_node == router_node:
                continue
            
            data = G.nodes[child_node]
            dtype = data.get("type", "Host")
            trust = data.get("trust", "Trusted")
            
            # Particle Color matching destination node
            if "Rogue" in trust or "Suspicious" in trust:
                p_color = c['danger']
            elif "Mobile" in dtype or "Smartphone" in dtype:
                p_color = "#38bdf8"
            elif "Printer" in dtype:
                p_color = "#a855f7"
            else:
                p_color = c['success']

            line = QGraphicsLineItem(gw_pos.x(), gw_pos.y(), child_pos.x(), child_pos.y())
            line.setPen(QPen(QColor(c['border']), 2, Qt.DashLine))
            line.setZValue(1)
            self.scene.addItem(line)
            
            # Add 2 staggered pulse particles per connection line for continuous flow effect
            p1 = PulseParticleItem(gw_pos, child_pos, color_hex=p_color)
            p1.progress = 0.0
            self.scene.addItem(p1)
            self.particles.append(p1)
            
            p2 = PulseParticleItem(gw_pos, child_pos, color_hex=p_color)
            p2.progress = 0.5
            self.scene.addItem(p2)
            self.particles.append(p2)

        # 3. Draw Node Items
        for node_id, pt in pos.items():
            data = G.nodes[node_id]
            is_gw = data.get("is_gw", False)
            ip = data.get("ip", "192.168.1.1")
            name = data.get("name", "Gateway")
            dtype = data.get("type", "Host")
            trust = data.get("trust", "Trusted")
            
            node_item = NodeGraphicsItem(node_id, ip, name, dtype, trust, is_gateway=is_gw)
            node_item.setPos(pt.x(), pt.y())
            self.scene.addItem(node_item)

        self.scene.setSceneRect(-420, -420, 840, 840)
        if self._active:
            self.pulse_timer.start()

    def set_active(self, active):
        self._active = bool(active)
        if self._active:
            self.pulse_timer.start()
        else:
            self.pulse_timer.stop()

    def _advance_animation(self):
        for p in self.particles:
            p.advance_pulse()
        for rw in self.radar_waves:
            rw.advance_wave()

    def closeEvent(self, event):
        self.pulse_timer.stop()
        super().closeEvent(event)
