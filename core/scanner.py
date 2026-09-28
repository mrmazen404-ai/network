# core/scanner.py
import socket
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, IP, srp
from PySide6.QtCore import QThread, Signal as pyqtSignal
from mac_vendor_lookup import MacLookup
from core.database import db
def is_randomized_mac(mac):
    """Check if MAC address has the local/randomized bit set (Private MAC used by iOS/Android)"""
    try:
        clean_mac = mac.replace(":", "").replace("-", "").lower()
        if len(clean_mac) >= 2:
            return clean_mac[1] in ["2", "6", "a", "e"]
    except Exception:
        pass
    return False

def infer_device_type(vendor="", ttl=None, hostname="", mac=""):
    """Enterprise Hybrid Fingerprinting: Identify Smartphones, Tablets, PCs, Routers, Printers"""
    v = vendor.lower()
    h = hostname.lower()
    
    if is_randomized_mac(mac) and ("unknown" in v or not v or "private" in v):
        return "📱 Smartphone / Private MAC"
        
    if any(k in v or k in h for k in ["apple", "iphone", "ipad"]):
        return "📱 Apple iOS / macOS"
    elif any(k in v or k in h for k in ["samsung", "xiaomi", "oneplus", "oppo", "vivo", "realme", "android", "huawei mobile"]):
        return "📱 Android Mobile Device"
    elif any(k in v or k in h for k in ["cisco", "tp-link", "d-link", "netgear", "huawei", "mikrotik", "ubiquiti", "zte", "asus", "router", "gateway"]):
        return "🌐 Router / Gateway"
    elif any(k in v or k in h for k in ["hp", "canon", "epson", "brother", "lexmark", "xerox", "printer"]):
        return "🖨️ Network Printer"
    elif any(k in v or k in h for k in ["lg", "sony", "roku", "tcl", "tv", "chromecast"]):
        return "📺 Smart TV / Streaming Device"
    
    if ttl is not None:
        if ttl <= 64:
            return "📱 Mobile / Linux Device"
        elif ttl <= 128:
            return "💻 Windows Workstation / Server"
        elif ttl <= 255:
            return "📡 Network Device / Router"
            
    if "win" in h or "desktop" in h or "laptop" in h:
        return "💻 Windows Workstation"
    return "💻 Network Host"

def ping_ip(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        res = subprocess.run(["ping", param, "1", "-w", "400", ip],
                             capture_output=True, text=True, timeout=1.0)
        return ip, (res.returncode == 0)
    except Exception:
        return ip, False

def get_system_arp_cache():
    """Extract ARP cache from OS system table (arp -a) to catch sleeping/silent devices"""
    cache = {}
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=2.0)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1]
                if ip.count(".") == 3 and ("-" in mac or ":" in mac):
                    clean_mac = mac.replace("-", ":").lower()
                    if len(clean_mac) == 17 and not ip.startswith("224.") and not ip.startswith("239.") and ip != "255.255.255.255":
                        cache[ip] = clean_mac
    except Exception:
        pass
    return cache

class DeviceScannerThread(QThread):
    device_found = pyqtSignal(dict)
    finished_scan = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, subnet=None):
        super().__init__()
        self.subnet = subnet or self._auto_subnet()
        self.mac_lookup = None
    
    def _auto_subnet(self):
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        ip = addr.address
                        netmask = addr.netmask or "255.255.255.0"
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        return str(network)
            return "192.168.1.0/24"
        except Exception:
            return "192.168.1.0/24"
    
    def run(self):
        try:
            try:
                self.mac_lookup = MacLookup()
                self.mac_lookup.update_vendors()
            except Exception:
                self.mac_lookup = None

            found_devices_map = {}
            
            # 1. Active ARP Sweep
            arp   = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            ans, _ = srp(ether/arp, timeout=2.5, verbose=0)
            
            for _, rcv in ans:
                mac = rcv.hwsrc.lower()
                ip  = rcv.psrc
                found_devices_map[mac] = {"ip": ip, "mac": mac, "ttl": rcv[IP].ttl if rcv.haslayer(IP) else None}
            
            # 2. Concurrent ICMP Ping Sweep (Wakes up sleeping smartphones / TV / IoT devices)
            net = ipaddress.IPv4Network(self.subnet, strict=False)
            ip_list = [str(host) for host in list(net.hosts())[:254]]
            
            active_ping_ips = set()
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(ping_ip, ip): ip for ip in ip_list}
                for future in as_completed(futures):
                    ip, is_up = future.result()
                    if is_up:
                        active_ping_ips.add(ip)
            
            # 3. Match Ping responses with OS System ARP Cache
            arp_cache = get_system_arp_cache()
            for ip in active_ping_ips:
                if ip in arp_cache:
                    mac = arp_cache[ip]
                    if mac not in found_devices_map:
                        found_devices_map[mac] = {"ip": ip, "mac": mac, "ttl": 64}
            
            # 4. Resolve Vendors, Hostnames, and Device Types
            devices = []
            for mac, dev_info in found_devices_map.items():
                ip = dev_info["ip"]
                mac = dev_info["mac"]
                ttl = dev_info.get("ttl")
                
                vendor = "Unknown"
                if is_randomized_mac(mac):
                    vendor = "Private/Randomized MAC"
                else:
                    try:
                        if self.mac_lookup:
                            vendor = self.mac_lookup.lookup(mac)
                    except Exception:
                        pass
                
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
                
                dev_type = infer_device_type(vendor, ttl, hostname, mac)
                
                is_new = db.upsert_device(ip, mac, vendor, hostname, dev_type)
                info = {
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "device_type": dev_type,
                    "is_new": is_new, "is_online": True
                }
                devices.append(info)
                self.device_found.emit(info)
            
            self.finished_scan.emit(devices)
        except Exception as e:
            self.error_occurred.emit(str(e))
