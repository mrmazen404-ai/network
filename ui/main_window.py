# ui/main_window.py
import qtawesome as qta
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, QMessageBox, QSystemTrayIcon, QMenu, QDialog)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction

from config import APP_NAME, APP_VERSION, get_app_stylesheet, set_current_theme, ENABLE_TOAST_NOTIFICATIONS, ENABLE_TRAY_NOTIFICATIONS, ENABLE_AUDIO_ALERTS
from core.database import db
from core.auth_db import auth_db
from core.network_monitor import RealtimeNetworkMonitor
from core.sound_engine import play_alert_sound
from ui.toast_notification import ToastManager
from ui.top_bar import TopBar
from ui.sidebar import Sidebar
from ui.bottom_bar import BottomBar

from ui.dashboard_tab import DashboardTab
from ui.topology_tab import TopologyTab
from ui.devices_tab import DevicesTab
from ui.packets_tab import PacketsTab
from ui.scanner_tab import ScannerTab
from ui.alerts_tab import AlertsTab
from ui.terminal_tab import TerminalTab
from ui.analytics_tab import AnalyticsTab
from ui.profile_tab import ProfileTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1360, 860)
        self.is_rtl = False
        self._active_page = 0
        
        # Remove standard OS window frame for custom titlebar controls
        self.setWindowFlags(Qt.FramelessWindowHint)
        
        self.toast_manager = ToastManager(self)
        self.net_monitor = None
        
        self._setup_ui()
        self._setup_system_tray()
        self._apply_theme("Cyberpunk")
        # Monitoring is intentionally manual: startup must remain responsive and predictable.

    def _setup_ui(self):
        # Header Top Bar
        self.top_bar = TopBar(self)
        self.top_bar.theme_changed.connect(self._apply_theme)
        self.top_bar.direction_toggled.connect(self._toggle_direction)
        
        # Sidebar Navigation
        self.sidebar = Sidebar(self)
        self.sidebar.nav_changed.connect(self._on_nav_changed)
        
        # Stacked Pages
        self.pages = QStackedWidget(self)
        
        self.tab_dashboard = DashboardTab(self)
        self.tab_topology  = TopologyTab(self)
        self.tab_devices   = DevicesTab(self)
        self.tab_packets   = PacketsTab(self)
        self.tab_scanner   = ScannerTab(self)
        self.tab_alerts    = AlertsTab(self)
        self.tab_terminal  = TerminalTab(self)
        self.tab_analytics = AnalyticsTab(self)
        self.tab_profile   = ProfileTab(self)
        self.tab_profile.logout_requested.connect(self._handle_logout)
        
        self.pages.addWidget(self.tab_dashboard) # 0
        self.pages.addWidget(self.tab_topology)  # 1
        self.pages.addWidget(self.tab_devices)   # 2
        self.pages.addWidget(self.tab_packets)   # 3
        self.pages.addWidget(self.tab_scanner)   # 4
        self.pages.addWidget(self.tab_alerts)    # 5
        self.pages.addWidget(self.tab_terminal)  # 6
        self.pages.addWidget(self.tab_analytics) # 7
        self.pages.addWidget(self.tab_profile)   # 8
        
        # Footer Bottom Bar
        self.bottom_bar = BottomBar(self)
        
        # Connect Signals
        self.tab_dashboard.alert_signal.connect(self._on_alert_received)
        self.tab_dashboard.speed_signal.connect(self.bottom_bar.update_speed)
        
        # Central Layout Assembly
        self.center_layout = QHBoxLayout()
        self.center_layout.setContentsMargins(0, 0, 0, 0)
        self.center_layout.setSpacing(0)
        self.center_layout.addWidget(self.sidebar)
        self.center_layout.addWidget(self.pages, stretch=1)
        
        center_widget = QWidget()
        center_widget.setLayout(self.center_layout)
        
        main_vbox = QVBoxLayout()
        main_vbox.setContentsMargins(0, 0, 0, 0)
        main_vbox.setSpacing(0)
        main_vbox.addWidget(self.top_bar)
        main_vbox.addWidget(center_widget, stretch=1)
        main_vbox.addWidget(self.bottom_bar)
        
        root_container = QWidget()
        root_container.setLayout(main_vbox)
        self.setCentralWidget(root_container)

    def _setup_system_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(qta.icon('fa5s.shield-alt', color='#00e5ff'))
        
        tray_menu = QMenu(self)
        act_show = QAction("Open Network Security Monitor", self)
        act_show.triggered.connect(self.showNormal)
        
        act_exit = QAction("Exit Application", self)
        act_exit.triggered.connect(self.close)
        
        tray_menu.addAction(act_show)
        tray_menu.addSeparator()
        tray_menu.addAction(act_exit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def _start_realtime_monitor(self):
        if self.net_monitor and self.net_monitor.isRunning():
            return
        self.net_monitor = RealtimeNetworkMonitor(interval_sec=15)
        self.net_monitor.device_connected.connect(self._on_device_connected)
        self.net_monitor.device_disconnected.connect(self._on_device_disconnected)
        self.net_monitor.scan_cycle_finished.connect(self.tab_devices.load_from_db)
        self.net_monitor.start()

    def start_realtime_monitor(self):
        """Explicit opt-in entry point for active LAN monitoring."""
        self._start_realtime_monitor()

    def stop_realtime_monitor(self):
        if self.net_monitor:
            self.net_monitor.stop()
            self.net_monitor = None

    def _on_device_connected(self, dev_info):
        ip = dev_info.get("ip", "")
        mac = dev_info.get("mac", "")
        dev_type = dev_info.get("device_type", "Network Host")
        title = "New Device Connected"
        msg = f"Device joined LAN: {ip} ({dev_type})\nMAC: {mac}"
        
        if ENABLE_AUDIO_ALERTS:
            play_alert_sound("success")

        if ENABLE_TOAST_NOTIFICATIONS:
            toast = self.toast_manager.show_toast(title, msg, category="success", data=dev_info, duration_ms=6000)
            toast.action_clicked.connect(self._on_toast_trust_device)
            
        if ENABLE_TRAY_NOTIFICATIONS and self.tray_icon:
            self.tray_icon.showMessage(title, f"{ip} ({dev_type}) connected", QSystemTrayIcon.Information, 4000)
            
        self.tab_devices.load_from_db()

    def _on_device_disconnected(self, dev_info):
        ip = dev_info.get("ip", "")
        dev_type = dev_info.get("device_type", "Network Host")
        title = "Device Disconnected"
        msg = f"Device went offline: {ip} ({dev_type})"
        
        if ENABLE_AUDIO_ALERTS:
            play_alert_sound("warning")

        if ENABLE_TOAST_NOTIFICATIONS:
            self.toast_manager.show_toast(title, msg, category="warning", data=dev_info, duration_ms=4000)
            
        if ENABLE_TRAY_NOTIFICATIONS and self.tray_icon:
            self.tray_icon.showMessage(title, f"{ip} went offline", QSystemTrayIcon.Warning, 3000)
            
        self.tab_devices.load_from_db()

    def _on_toast_trust_device(self, dev_info):
        mac = dev_info.get("mac", "")
        if mac:
            db.update_device_meta(mac, trust_status="Trusted")
            self.tab_devices.load_from_db()
            self.toast_manager.show_toast("Device Trusted", f"Marked {dev_info.get('ip')} as Trusted!", category="info")

    def _on_nav_changed(self, index):
        if self._active_page == 7 and index != 7:
            self.tab_analytics.set_active(False)
        if self._active_page == 1 and index != 1:
            self.tab_topology.set_active(False)
        if self._active_page == 2 and index != 2:
            self.tab_devices.set_active(False)
        self.pages.setCurrentIndex(index)
        if index == 1:
            self.tab_topology.set_active(True)
            self.tab_topology.render_graph()
        elif index == 2:
            self.tab_devices.set_active(True)
            self.tab_devices.load_from_db()
        elif index == 7:
            self.tab_analytics.set_active(True)
            self.tab_analytics.render_matplot_charts()
        elif index == 8:
            self.tab_profile.load_user_profile()
        self._active_page = index

    def _on_alert_received(self, alert):
        self.tab_alerts.add_alert(alert)
        sev = alert.get("severity", "")
        msg = alert.get("message", "")
        atype = alert.get("type", "Security Incident")
        
        if sev in ("CRITICAL", "HIGH"):
            self.top_bar.set_threat_status(True, msg)
            if ENABLE_AUDIO_ALERTS:
                play_alert_sound("danger")
            if ENABLE_TOAST_NOTIFICATIONS:
                self.toast_manager.show_toast(f"CRITICAL: {atype}", msg, category="danger", data=alert, duration_ms=8000)
            if ENABLE_TRAY_NOTIFICATIONS and self.tray_icon:
                self.tray_icon.showMessage(f"ALERT: {atype}", msg, QSystemTrayIcon.Critical, 5000)

    def _apply_theme(self, theme_name):
        set_current_theme(theme_name)
        qss = get_app_stylesheet(theme_name)
        self.setStyleSheet(qss)
        
        # Update only lightweight dynamic styles; do not rebuild widget trees or signals.
        self.tab_dashboard.update_theme_styles()
        if self.pages.currentIndex() == 1:
            self.tab_topology.render_graph()
        if self.pages.currentIndex() == 7:
            self.tab_analytics.update_theme_styles()

    def _toggle_direction(self):
        self.is_rtl = not self.is_rtl
        if self.is_rtl:
            self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        else:
            self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

    def _handle_logout(self):
        self.close()
        from ui.auth_dialog import AuthDialog
        dialog = AuthDialog()
        if dialog.exec_() == QDialog.Accepted:
            new_win = MainWindow()
            new_win.show()

    def closeEvent(self, event):
        try:
            self.tab_dashboard.stop_all()
            self.tab_analytics.set_active(False)
            self.tab_topology.set_active(False)
            self.tab_devices.set_active(False)
            if self.net_monitor:
                self.net_monitor.stop()
            if self.tray_icon:
                self.tray_icon.hide()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Application shutdown failed: %s", exc)
        event.accept()
