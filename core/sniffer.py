# core/sniffer.py
import logging
import queue
import socket
import threading
import time
from collections import deque

from PySide6.QtCore import QThread, Signal as pyqtSignal
from scapy.all import IFACES, conf, sniff

logger = logging.getLogger(__name__)
conf.sniff_promisc = True


def get_active_sniff_iface():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        if hasattr(IFACES, "data"):
            for dev in IFACES.data.values():
                if getattr(dev, "ip", None) == local_ip:
                    return dev
                if hasattr(dev, "ips") and isinstance(dev.ips, dict):
                    if any(local_ip in ip_list for ip_list in dev.ips.values()):
                        return dev
    except Exception:
        logger.exception("Unable to determine active capture interface")
    return None


class SnifferThread(QThread):
    """Capture packets without touching UI code; consumers drain the bounded queue."""
    # Retained for compatibility; it is emitted at most four times per second with batches.
    packet_batch = pyqtSignal(list)
    packet_captured = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    health_changed = pyqtSignal(dict)

    def __init__(self, iface=None, max_buffer=5000, queue_size=10000):
        super().__init__()
        self.iface = iface or get_active_sniff_iface()
        self.running = False
        self.raw_packet_buffer = deque(maxlen=max_buffer)
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self._dropped = 0
        self._dropped_lock = threading.Lock()
        self._ui_batch = []
        self._last_ui_emit = time.monotonic()

    def dropped_count(self):
        with self._dropped_lock:
            return self._dropped

    def _increment_dropped(self):
        with self._dropped_lock:
            self._dropped += 1

    def run(self):
        self.running = True
        self.health_changed.emit({"state": "running", "queue_size": self.packet_queue.maxsize})
        while self.running:
            try:
                sniff(
                    iface=self.iface,
                    prn=self._emit,
                    store=False,
                    timeout=0.25,
                    promisc=True,
                )
                self._flush_ui_batch(force=True)
            except Exception as exc:
                if self.running:
                    logger.exception("Packet capture failed")
                    self.error_occurred.emit(str(exc))
                break
        self._flush_ui_batch(force=True)
        self.health_changed.emit({"state": "stopped", "dropped": self.dropped_count()})

    def _emit(self, packet):
        if not self.running:
            return
        self.raw_packet_buffer.append(packet)
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # Backpressure: preserve UI responsiveness instead of blocking capture.
            self._increment_dropped()
        self._ui_batch.append(packet)
        self._flush_ui_batch()

    def _flush_ui_batch(self, force=False):
        now = time.monotonic()
        if self._ui_batch and (force or now - self._last_ui_emit >= 0.25):
            batch = self._ui_batch[:200]
            del self._ui_batch[:len(batch)]
            self.packet_batch.emit(batch)
            self._last_ui_emit = now

    def get_captured_packets(self):
        return list(self.raw_packet_buffer)

    def clear_packet_buffer(self):
        self.raw_packet_buffer.clear()

    def stop(self):
        self.running = False
        if self.isRunning():
            self.wait(5000)
