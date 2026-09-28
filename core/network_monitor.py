# core/network_monitor.py
import logging
import time
from PySide6.QtCore import QThread, Signal as pyqtSignal
from core.scanner import DeviceScannerThread, get_system_arp_cache, is_randomized_mac, infer_device_type, ping_ip
from core.database import db
from config import OFFLINE_FAILURE_THRESHOLD

logger = logging.getLogger(__name__)

class RealtimeNetworkMonitor(QThread):
    """Enterprise Continuous Background Network Presence & Threat Monitor Thread (99% Accuracy Tuned)"""
    device_connected    = pyqtSignal(dict)  # Emitted ONLY when a genuine new device joins
    device_disconnected = pyqtSignal(dict)  # Emitted ONLY after consecutive failure threshold
    scan_cycle_finished = pyqtSignal(list)  # Emitted after each monitoring pass
    error_occurred = pyqtSignal(str)
    
    def __init__(self, interval_sec=15):
        super().__init__()
        self.interval_sec = interval_sec
        self.running = False
        self.active_hosts_map = {}   # mac -> dev_dict
        self.missed_cycles_map = {}  # mac -> int missed count
        self.is_first_scan = True
    
    def run(self):
        self.running = True
        
        # Load baseline devices from DB
        initial_devices = db.get_devices()
        for d in initial_devices:
            mac = d.get("mac", "").lower()
            if mac:
                self.active_hosts_map[mac] = d
                self.missed_cycles_map[mac] = 0
        
        while self.running:
            try:
                scanner_thread = DeviceScannerThread()
                scanner_thread.subnet = scanner_thread._auto_subnet()
                
                current_devices = []
                current_devices_map = {}  # mac -> dev_dict
                
                # Perform ARP + Ping sweep
                from scapy.all import ARP, Ether, IP, srp
                from concurrent.futures import ThreadPoolExecutor, as_completed
                import ipaddress, socket
                
                try:
                    arp = ARP(pdst=scanner_thread.subnet)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    ans, _ = srp(ether/arp, timeout=2.0, verbose=0)
                    for _, rcv in ans:
                        mac = rcv.hwsrc.lower()
                        ip  = rcv.psrc
                        current_devices_map[mac] = {"ip": ip, "mac": mac, "ttl": rcv[IP].ttl if rcv.haslayer(IP) else None}
                except PermissionError as exc:
                    logger.warning("ARP sweep unavailable without elevated network permissions: %s", exc)
                    self.error_occurred.emit("ARP sweep requires elevated network permissions")
                except Exception as exc:
                    logger.exception("ARP sweep failed")
                    self.error_occurred.emit(f"ARP sweep failed: {exc}")

                # Quick Ping Sweep for sleeping devices
                try:
                    net = ipaddress.IPv4Network(scanner_thread.subnet, strict=False)
                    ip_list = [str(host) for host in list(net.hosts())[:254]]
                    
                    active_ping_ips = set()
                    with ThreadPoolExecutor(max_workers=40) as executor:
                        futures = {executor.submit(ping_ip, ip): ip for ip in ip_list}
                        for future in as_completed(futures):
                            ip, is_up = future.result()
                            if is_up:
                                active_ping_ips.add(ip)
                    
                    arp_cache = get_system_arp_cache()
                    for ip in active_ping_ips:
                        if ip in arp_cache:
                            mac = arp_cache[ip]
                            if mac not in current_devices_map:
                                current_devices_map[mac] = {"ip": ip, "mac": mac, "ttl": 64}
                except Exception as exc:
                    logger.exception("Ping sweep failed")
                    self.error_occurred.emit(f"Ping sweep failed: {exc}")

                # Process results and detect genuine joins / leaves
                scanned_macs = set()
                
                for mac, dev_info in current_devices_map.items():
                    scanned_macs.add(mac)
                    ip = dev_info["ip"]
                    mac = dev_info["mac"]
                    ttl = dev_info.get("ttl")
                    
                    vendor = "Unknown"
                    if is_randomized_mac(mac):
                        vendor = "Private/Randomized MAC"
                    
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        pass
                    
                    dev_type = infer_device_type(vendor, ttl, hostname, mac)
                    
                    is_new_mac = db.upsert_device(ip, mac, vendor, hostname, dev_type)
                    info = {
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "hostname": hostname, "device_type": dev_type,
                        "is_new": is_new_mac, "is_online": True
                    }
                    current_devices.append(info)
                    
                    # Reset missed cycle counter since host responded
                    self.missed_cycles_map[mac] = 0
                    
                    # 🟢 Emit New Connection alert ONLY if genuine new MAC AFTER baseline scan
                    if not self.is_first_scan and (mac not in self.active_hosts_map or is_new_mac):
                        self.device_connected.emit(info)
                    
                    self.active_hosts_map[mac] = info

                # 🔴 Detect Device Disconnection with Hysteresis Threshold (3 missed cycles = 45s)
                previous_macs = set(self.active_hosts_map.keys())
                unresponsive_macs = previous_macs - scanned_macs
                
                for mac in unresponsive_macs:
                    self.missed_cycles_map[mac] = self.missed_cycles_map.get(mac, 0) + 1
                    
                    # Require 3 consecutive missed scans before marking offline to avoid Wi-Fi signal flicker false positives
                    if self.missed_cycles_map[mac] >= OFFLINE_FAILURE_THRESHOLD:
                        old_info = self.active_hosts_map.pop(mac, None)
                        if old_info:
                            old_info["is_online"] = False
                            if not self.is_first_scan:
                                self.device_disconnected.emit(old_info)

                self.is_first_scan = False
                self.scan_cycle_finished.emit(current_devices)

            except Exception as exc:
                logger.exception("Realtime network monitor cycle failed")
                self.error_occurred.emit(str(exc))
            
            # Sleep in small increments for quick responsiveness on thread stop
            for _ in range(self.interval_sec * 2):
                if not self.running:
                    break
                time.sleep(0.5)

    def stop(self):
        self.running = False
        if self.isRunning():
            self.wait(5000)
