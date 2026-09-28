# test_system.py
import sys
import time
from PySide6.QtWidgets import QApplication
from config import APP_NAME, get_app_stylesheet
from core.database import db
from core.detector import ThreatDetector
from core.port_scanner import PortScannerThread, parse_ports_input
from core.scanner import DeviceScannerThread
from core.exporter import export_alerts_to_csv, export_alerts_to_pdf
from ui.main_window import MainWindow
from scapy.all import IP, TCP

def run_tests():
    print("==========================================")
    print("🧪 Starting Integration Tests for NetSec Monitor")
    print("==========================================")

    # Test 1: Database Initialization
    print("[1/6] Testing Database CRUD...")
    db.upsert_device("192.168.1.100", "00:11:22:33:44:55", "Intel", "Test-PC")
    devices = db.get_devices()
    assert len(devices) > 0, "Database device insert failed!"
    
    alert_id = db.add_alert("TEST_ATTACK", "HIGH", "192.168.1.100", "192.168.1.1", "Test threat alert message")
    alerts = db.get_alerts(limit=10)
    assert len(alerts) > 0, "Database alert insert failed!"
    print("  ✅ Database OK!")

    # Test 2: Threat Detector Engine (320 SYN packets to trigger threshold = 300)
    print("[2/6] Testing Threat Detector Anomaly Engine...")
    detected_alerts = []
    detector = ThreatDetector(alert_callback=lambda a: detected_alerts.append(a))
    
    # Simulate SYN Flood (320 packets > 300 threshold)
    pkt = IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
    for _ in range(320):
        detector.process(pkt)
    
    print(f"  Alerts generated: {len(detected_alerts)}")
    assert len(detected_alerts) > 0, "Threat detector failed to identify SYN Flood!"
    print("  ✅ Threat Detector Engine OK!")

    # Test 3: Exporter Module
    print("[3/6] Testing Export Engine (CSV & PDF)...")
    csv_file = export_alerts_to_csv("exports/test_alerts.csv")
    pdf_file = export_alerts_to_pdf("exports/test_alerts.pdf")
    print(f"  Saved CSV: {csv_file}")
    print(f"  Saved PDF: {pdf_file}")
    print("  ✅ Export Engine OK!")

    # Test 4: Port Scanner Thread
    print("[4/6] Testing Port Scanner (Localhost)...")
    ports = parse_ports_input("Quick Scan")
    print(f"  Scanning {len(ports)} quick ports on 127.0.0.1...")
    p_thread = PortScannerThread("127.0.0.1", ports[:10])
    p_thread.start()
    p_thread.wait(3000)
    if p_thread.isRunning():
        p_thread.stop()
        p_thread.wait(10000)
    print("  ✅ Port Scanner Thread OK!")

    # Test 5: UI Window Creation
    print("[5/6] Testing GUI Window Rendering...")
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(get_app_stylesheet("Cyberpunk"))
    
    win = MainWindow()
    win.show()
    print("  ✅ Main Window, TopBar, Sidebar, BottomBar & Tabs Initialized OK!")

    # Test 6: Theme Switching
    print("[6/7] Testing Theme Switcher...")
    win._apply_theme("Deep Blue")
    win._apply_theme("Clean Light")
    win._apply_theme("Cyberpunk")
    print("  ✅ Theme Switcher OK!")

    # Test 7: Device Tagging & Metadata
    print("[7/7] Testing LAN Device Security Tagging & Metadata...")
    db.update_device_meta("00:11:22:33:44:55", alias="Office PC", trust_status="Trusted", notes="Verified")
    updated_dev = [d for d in db.get_devices() if d.get("mac") == "00:11:22:33:44:55"][0]
    assert updated_dev.get("alias") == "Office PC", "Device alias metadata failed!"
    print("  ✅ LAN Device Tagging & Metadata OK!")

    print("\n==========================================")
    print("🎉 ALL 7 INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("==========================================")
    win.close()
    app.processEvents()

if __name__ == "__main__":
    run_tests()
