# core/database.py
import sqlite3
import threading
from datetime import datetime, timedelta
from config import DB_PATH, DB_RETENTION_DAYS

class Database:
    _lock = threading.Lock()
    
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()
        self._prune_old_records(retention_days=DB_RETENTION_DAYS)
    
    def _create_tables(self):
        with self._lock:
            cur = self.conn.cursor()
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, mac TEXT, vendor TEXT,
                hostname TEXT, device_type TEXT,
                first_seen TEXT, last_seen TEXT,
                UNIQUE(mac)
            )""")
            
            # Auto-migrate schema if columns are missing from previous db
            cur.execute("PRAGMA table_info(devices)")
            cols = [row[1] for row in cur.fetchall()]
            if "device_type" not in cols:
                cur.execute("ALTER TABLE devices ADD COLUMN device_type TEXT DEFAULT 'Network Host'")
            if "alias" not in cols:
                cur.execute("ALTER TABLE devices ADD COLUMN alias TEXT DEFAULT ''")
            if "trust_status" not in cols:
                cur.execute("ALTER TABLE devices ADD COLUMN trust_status TEXT DEFAULT 'Unknown'")
            if "notes" not in cols:
                cur.execute("ALTER TABLE devices ADD COLUMN notes TEXT DEFAULT ''")

            cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                severity TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                message TEXT
            )""")
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS open_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, port INTEGER, service TEXT,
                scanned_at TEXT
            )""")
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                download_kbps REAL,
                upload_kbps REAL,
                packets_count INTEGER
            )""")
            
            # Enterprise SQL Performance Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_stats(timestamp)")
            
            self.conn.commit()

    def _prune_old_records(self, retention_days=30):
        """Data Retention Policy: Auto-prune logs older than N days"""
        cutoff = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM traffic_stats WHERE timestamp < ?", (cutoff,))
            self.conn.commit()

    # ---------- Devices ----------
    def upsert_device(self, ip, mac, vendor="Unknown", hostname="", device_type="Network Host"):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_new = False
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM devices WHERE mac=?", (mac,))
            row = cur.fetchone()
            if row:
                cur.execute("""UPDATE devices SET ip=?, last_seen=?, vendor=?, hostname=?, device_type=?
                               WHERE mac=?""", (ip, now, vendor, hostname, device_type, mac))
            else:
                is_new = True
                cur.execute("""INSERT INTO devices(ip,mac,vendor,hostname,device_type,alias,trust_status,notes,first_seen,last_seen)
                               VALUES(?,?,?,?,?,'','Unknown','',?,?)""",
                            (ip, mac, vendor, hostname, device_type, now, now))
            self.conn.commit()
            
        if is_new:
            self.add_alert(
                "New_Device", "MEDIUM", ip, "LAN",
                f"⚠️ Rogue/New device detected on LAN: {ip} ({mac} - {vendor})"
            )
        return is_new
    
    def update_device_meta(self, mac, alias=None, trust_status=None, notes=None):
        with self._lock:
            cur = self.conn.cursor()
            if alias is not None:
                cur.execute("UPDATE devices SET alias=? WHERE mac=?", (alias, mac))
            if trust_status is not None:
                cur.execute("UPDATE devices SET trust_status=? WHERE mac=?", (trust_status, mac))
            if notes is not None:
                cur.execute("UPDATE devices SET notes=? WHERE mac=?", (notes, mac))
            self.conn.commit()

    def delete_device(self, mac):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM devices WHERE mac=?", (mac,))
            self.conn.commit()
    
    def get_devices(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(r) for r in cur.fetchall()]
    
    # ---------- Alerts ----------
    def add_alert(self, alert_type, severity, src_ip, dst_ip, message):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""INSERT INTO alerts(timestamp,type,severity,src_ip,dst_ip,message)
                           VALUES(?,?,?,?,?,?)""",
                        (now, alert_type, severity, src_ip, dst_ip, message))
            self.conn.commit()
            return cur.lastrowid
    
    def get_alerts(self, limit=200):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def get_recent_alerts(self, hours=1):
        cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM alerts WHERE timestamp >= ? ORDER BY id DESC", (cutoff,))
            return [dict(r) for r in cur.fetchall()]
    
    def clear_alerts(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM alerts")
            self.conn.commit()

    # ---------- Open Ports ----------
    def save_open_ports(self, ip, ports_info):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM open_ports WHERE ip=?", (ip,))
            for p, svc in ports_info:
                cur.execute("""INSERT INTO open_ports(ip,port,service,scanned_at)
                               VALUES(?,?,?,?)""", (ip, p, svc, now))
            self.conn.commit()
    
    def get_open_ports(self, ip=None):
        with self._lock:
            cur = self.conn.cursor()
            if ip:
                cur.execute("SELECT * FROM open_ports WHERE ip=?", (ip,))
            else:
                cur.execute("SELECT * FROM open_ports ORDER BY scanned_at DESC")
            return [dict(r) for r in cur.fetchall()]
    
    # ---------- Traffic Statistics ----------
    def add_traffic_stat(self, down, up, pkt_count):
        self.add_traffic_stats_batch([(down, up, pkt_count)])

    def add_traffic_stats_batch(self, records):
        if not records:
            return
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            cur = self.conn.cursor()
            cur.executemany(
                """INSERT INTO traffic_stats(timestamp,download_kbps,upload_kbps,packets_count)
                   VALUES(?,?,?,?)""",
                [(now, down, up, pkt_count) for down, up, pkt_count in records],
            )
            self.conn.commit()
    
    def close(self):
        self.conn.close()

db = Database()
