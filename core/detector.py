# core/detector.py
import time
import socket
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ARP, ICMP
from config import SYN_FLOOD_THRESHOLD, DOS_PPS_THRESHOLD
from core.database import db

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
        
    try:
        # Fallback via getaddrinfo
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
        
    return "127.0.0.1"

class ThreatDetector:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.arp_table   = {}  # ip -> set(macs)
        self.syn_track   = defaultdict(deque)
        self.pkt_track   = deque()
        self.icmp_track  = defaultdict(deque)
        self.udp_track   = defaultdict(deque)
        self.last_alert  = {}
        self.last_cleanup = time.time()
        self.local_ip    = get_local_ip()
    
    def _can_alert(self, key, cooldown=15):
        now = time.time()
        if key not in self.last_alert or now - self.last_alert[key] > cooldown:
            self.last_alert[key] = now
            return True
        return False
    
    def _fire(self, atype, severity, src, dst, msg):
        db.add_alert(atype, severity, src, dst, msg)
        if self.alert_callback:
            self.alert_callback({
                "type": atype, "severity": severity,
                "src": src, "dst": dst, "message": msg,
                "time": time.strftime("%H:%M:%S")
            })

    def _cleanup_old_entries(self, now):
        """Periodically prune stale IP keys to prevent memory leak"""
        if now - self.last_cleanup < 10:
            return
        self.last_cleanup = now
        
        stale_syn = [ip for ip, d in self.syn_track.items() if not d or now - d[-1] > 15]
        for ip in stale_syn:
            del self.syn_track[ip]
            
        stale_icmp = [ip for ip, d in self.icmp_track.items() if not d or now - d[-1] > 10]
        for ip in stale_icmp:
            del self.icmp_track[ip]

        stale_udp = [ip for ip, d in self.udp_track.items() if not d or now - d[-1] > 10]
        for ip in stale_udp:
            del self.udp_track[ip]

        if hasattr(self, "_pscan"):
            stale_pscan = [k for k, entry in self._pscan.items() if now - entry["start"] > 30]
            for k in stale_pscan:
                del self._pscan[k]

        stale_alerts = [k for k, t in self.last_alert.items() if now - t > 60]
        for k in stale_alerts:
            del self.last_alert[k]
    
    def process(self, pkt):
        now = time.time()
        self._cleanup_old_entries(now)
        
        # 1) DoS packet-rate detection: count external IP traffic only.
        count_for_dos = pkt.haslayer(IP) and pkt[IP].src not in ("127.0.0.1", self.local_ip)
        if count_for_dos:
            self.pkt_track.append(now)
            while self.pkt_track and now - self.pkt_track[0] > 1:
                self.pkt_track.popleft()
            if len(self.pkt_track) > DOS_PPS_THRESHOLD and self._can_alert("dos_general", 15):
                self._fire("DoS", "HIGH", "N/A", "N/A",
                    f"⚠️ High external IP packet rate detected: {len(self.pkt_track)} pkt/s")
        
        # 2) ARP Spoofing Detection
        if pkt.haslayer(ARP):
            self._check_arp(pkt)
        
        # 3) SYN Flood & Port Scan (Ignore local loopback & local host)
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip != "127.0.0.1" and src_ip != self.local_ip:
                self._check_syn(pkt, now)
                self._check_port_scan(pkt, now)
        
        # 4) ICMP Flood
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip != "127.0.0.1" and src_ip != self.local_ip:
                self._check_icmp(pkt, now)
        
        # 5) UDP Flood
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip != "127.0.0.1" and src_ip != self.local_ip:
                self._check_udp(pkt, now)
    
    def _check_arp(self, pkt):
        if pkt[ARP].op == 2:  # Reply
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.lower()
            
            if ip not in self.arp_table:
                self.arp_table[ip] = {mac}
            else:
                # Multi-homed Wi-Fi routers (2.4G/5G/mesh) can legitimate use up to 2-3 MACs for gateway IP
                if mac not in self.arp_table[ip]:
                    if len(self.arp_table[ip]) >= 3:
                        if self._can_alert(f"arp_{ip}", 15):
                            old_macs = ", ".join(list(self.arp_table[ip]))
                            self._fire("ARP_Spoofing", "CRITICAL", ip, "N/A",
                                f"⚠️ ARP Spoofing! IP {ip} changed MACs: {old_macs} -> {mac}")
                    else:
                        self.arp_table[ip].add(mac)
    
    def _check_syn(self, pkt, now):
        tcp = pkt[TCP]
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN only
            src = pkt[IP].src
            d   = self.syn_track[src]
            d.append(now)
            while d and now - d[0] > 10:
                d.popleft()
            
            if len(d) > SYN_FLOOD_THRESHOLD:
                if self._can_alert(f"syn_{src}", 15):
                    self._fire("SYN_Flood", "HIGH", src, pkt[IP].dst,
                        f"⚠️ SYN Flood from {src} ({len(d)} SYN/10s)")
    
    def _check_port_scan(self, pkt, now):
        tcp = pkt[TCP]
        if tcp.flags & 0x02:
            key = f"pscan_{pkt[IP].src}"
            if not hasattr(self, "_pscan"):
                self._pscan = defaultdict(lambda: {"ports": set(), "start": now})
            entry = self._pscan[key]
            if now - entry["start"] > 5:
                entry["ports"].clear()
                entry["start"] = now
            entry["ports"].add(tcp.dport)
            
            if len(entry["ports"]) > 40:
                if self._can_alert(key, 15):
                    self._fire("Port_Scan", "MEDIUM", pkt[IP].src, pkt[IP].dst,
                        f"🔍 Port scanning activity from {pkt[IP].src} "
                        f"({len(entry['ports'])} ports / 5s)")
    
    def _check_icmp(self, pkt, now):
        src = pkt[IP].src
        d = self.icmp_track[src]
        d.append(now)
        while d and now - d[0] > 1:
            d.popleft()
        if len(d) > 200:
            if self._can_alert(f"icmp_{src}", 15):
                self._fire("ICMP_Flood", "MEDIUM", src, pkt[IP].dst,
                    f"⚠️ ICMP Flood from {src} ({len(d)} pkt/s)")
    
    def _check_udp(self, pkt, now):
        src = pkt[IP].src
        d = self.udp_track[src]
        d.append(now)
        while d and now - d[0] > 1:
            d.popleft()
        if len(d) > 800:
            if self._can_alert(f"udp_{src}", 15):
                self._fire("UDP_Flood", "MEDIUM", src, pkt[IP].dst,
                    f"⚠️ UDP Flood from {src} ({len(d)} pkt/s)")
