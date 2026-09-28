# core/packet_pipeline.py
"""Bounded packet analysis pipeline that keeps expensive work off the Qt UI thread."""
import logging
import queue
import threading
import time
from collections import Counter

from PySide6.QtCore import QThread, Signal as pyqtSignal
from scapy.all import IP

from core.detector import ThreatDetector

logger = logging.getLogger(__name__)


class PacketAnalyzerThread(QThread):
    stats_ready = pyqtSignal(dict)
    alert_signal = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, packet_queue, dropped_counter, parent=None):
        super().__init__(parent)
        self.packet_queue = packet_queue
        self.dropped_counter = dropped_counter
        self._stop_event = threading.Event()
        self._processed = 0
        self._talkers = Counter()
        self._last_emit = time.monotonic()
        self._last_total = 0

    def _on_alert(self, alert):
        self.alert_signal.emit(alert)

    def run(self):
        self._stop_event.clear()
        detector = ThreatDetector(alert_callback=self._on_alert)
        try:
            while not self._stop_event.is_set():
                processed_batch = 0
                while processed_batch < 1000 and not self._stop_event.is_set():
                    try:
                        packet = self.packet_queue.get(timeout=0.05)
                    except queue.Empty:
                        break
                    try:
                        detector.process(packet)
                        if packet.haslayer(IP):
                            self._talkers[packet[IP].src] += 1
                        self._processed += 1
                    except Exception as exc:
                        logger.exception("Packet analysis failed")
                        self.error_occurred.emit(str(exc))
                    finally:
                        self.packet_queue.task_done()
                    processed_batch += 1

                now = time.monotonic()
                if now - self._last_emit >= 0.25:
                    current_total = self._processed
                    self.stats_ready.emit({
                        "processed": current_total,
                        "rate": (current_total - self._last_total) / max(now - self._last_emit, 0.001),
                        "dropped": self.dropped_counter(),
                        "talkers": dict(self._talkers.most_common(20)),
                        "queue_size": self.packet_queue.qsize(),
                    })
                    self._last_total = current_total
                    self._last_emit = now
        except Exception as exc:
            logger.exception("Packet analyzer stopped unexpectedly")
            self.error_occurred.emit(str(exc))

    def stop(self):
        self._stop_event.set()
        if self.isRunning():
            self.wait(5000)
