# core/port_scanner.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtCore import QThread, Signal as pyqtSignal
from core.database import db

SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 137: "NetBIOS-Name", 138: "NetBIOS-Datagram",
    139: "NetBIOS-Session", 143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "ISAKMP", 514: "Syslog",
    587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 3000: "Dev-Web", 3306: "MySQL", 3389: "RDP", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter/Web", 9000: "SonarQube",
    9200: "Elasticsearch", 11211: "Memcached", 25565: "Minecraft", 27017: "MongoDB"
}
MAX_SCAN_PORTS = 4096

def get_port_risk_rating(port, service_name=""):
    """
    Evaluates Port Vulnerability & Risk Rating:
    Returns (risk_level_str, color_category, details_advice_str)
    """
    p = int(port)
    
    # 🔴 CRITICAL / HIGH RISK: Unencrypted Cleartext / Ransomware Vector
    if p in (23, 21, 445, 139):
        if p == 23:
            return "CRITICAL RISK", "danger", "Telnet unencrypted remote shell. High vulnerability. Migrate to SSH (Port 22)."
        elif p == 21:
            return "HIGH RISK", "danger", "FTP cleartext credentials. Sensitive data exposed. Migrate to SFTP/FTPS."
        elif p in (445, 139):
            return "HIGH RISK", "danger", "SMB File Sharing enabled. Ensure patch for EternalBlue & ransomware vectors."

    # 🟡 MEDIUM RISK: Remote Management / Web Interfaces / Databases
    if p in (80, 8080, 3389, 5900, 1433, 3306, 5432, 27017, 6379):
        if p in (80, 8080):
            return "MEDIUM RISK", "warning", "HTTP Plaintext Web Management Interface. Enable TLS/HTTPS certificate."
        elif p in (3389, 5900):
            return "MEDIUM RISK", "warning", "Remote Desktop / VNC Interface. Enforce strong NLA authentication & VPN."
        elif p in (1433, 3306, 5432, 27017, 6379):
            return "MEDIUM RISK", "warning", f"Database Service ({service_name}). Ensure strict Firewall ACLs & strong password."

    # 🟢 LOW RISK / SECURE: Encrypted Protocol Channels
    if p in (443, 8443, 22, 993, 995, 465):
        return "SECURE (LOW)", "success", "Encrypted Secure Channel (SSL/TLS or SSH)."

    return "INFORMATIONAL", "info", "Standard network service endpoint."

def parse_ports_input(mode_str, custom_input=""):
    if "Quick Scan" in mode_str:
        return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017]
    elif "Common Ports" in mode_str:
        return list(SERVICES.keys())
    elif "Standard Range (1-1024)" in mode_str:
        return list(range(1, 1025))
    else:
        ports = set()
        for part in custom_input.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    start, end = int(start), int(end)
                    if not (1 <= start <= end <= 65535):
                        continue
                    if end - start + 1 <= MAX_SCAN_PORTS:
                        ports.update(range(start, end + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
        if len(ports) > MAX_SCAN_PORTS:
            return []
        return sorted(list(ports))

def _grab_banner(ip, port, timeout=0.6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(128).decode("utf-8", "replace").strip()
        s.close()
        if banner:
            first_line = banner.splitlines()[0]
            return first_line[:25]
    except Exception:
        pass
    return ""

class PortScannerThread(QThread):
    port_open     = pyqtSignal(int, str, str, str, str)  # port, service, banner, risk_rating, details
    progress      = pyqtSignal(int, int)
    finished_scan = pyqtSignal(list)
    
    def __init__(self, ip, ports=None):
        super().__init__()
        self.ip    = ip
        requested_ports = list(SERVICES.keys()) if ports is None else ports
        self.ports = [p for p in requested_ports if 1 <= int(p) <= 65535][:MAX_SCAN_PORTS]
        self.running = True
    
    @staticmethod
    def _check(ip, port, timeout=0.5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return port, r == 0
        except Exception:
            return port, False
    
    def run(self):
        open_ports = []
        ports_info = []
        done = 0
        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = {ex.submit(self._check, self.ip, p): p for p in self.ports}
            for f in as_completed(futures):
                if not self.running:
                    break
                port, is_open = f.result()
                done += 1
                self.progress.emit(done, len(self.ports))
                if is_open:
                    svc = SERVICES.get(port, "Unknown Service")
                    banner = _grab_banner(self.ip, port)
                    if banner:
                        svc_str = f"{svc} ({banner})"
                    else:
                        svc_str = svc
                        
                    risk_lvl, color_cat, details = get_port_risk_rating(port, svc)
                    
                    open_ports.append(port)
                    ports_info.append((port, svc_str))
                    self.port_open.emit(port, svc_str, risk_lvl, color_cat, details)
        
        db.save_open_ports(self.ip, ports_info)
        self.finished_scan.emit(open_ports)

    def stop(self):
        self.running = False
