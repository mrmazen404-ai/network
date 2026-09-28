# core/speed_monitor.py
import threading
import time

import psutil
from PySide6.QtCore import QThread, Signal as pyqtSignal

from core.database import db


class SpeedMonitorThread(QThread):
    stats_updated = pyqtSignal(float, float, int)

    def __init__(self):
        super().__init__()
        self.running = False
        self._stop_event = threading.Event()

    def run(self):
        self.running = True
        self._stop_event.clear()
        old = psutil.net_io_counters()
        old_pkt = old.packets_recv + old.packets_sent
        pending_stats = []
        last_flush = time.monotonic()

        while self.running and not self._stop_event.wait(1.0):
            new = psutil.net_io_counters()
            down = max(0.0, (new.bytes_recv - old.bytes_recv) / 1024.0)
            up = max(0.0, (new.bytes_sent - old.bytes_sent) / 1024.0)
            pkts = max(0, (new.packets_recv + new.packets_sent) - old_pkt)
            self.stats_updated.emit(down, up, pkts)
            pending_stats.append((down, up, pkts))
            if time.monotonic() - last_flush >= 5.0:
                db.add_traffic_stats_batch(pending_stats)
                pending_stats.clear()
                last_flush = time.monotonic()
            old = new
            old_pkt = new.packets_recv + new.packets_sent

        if pending_stats:
            db.add_traffic_stats_batch(pending_stats)

    def stop(self):
        self.running = False
        self._stop_event.set()
        if self.isRunning():
            self.wait(5000)
