# core/sound_engine.py
import threading
import platform
import time

def play_alert_sound(category="info"):
    """Enterprise Audio Alert Chime Engine using native Windows winsound / system audio"""
    def _chime():
        try:
            if platform.system().lower() == "windows":
                import winsound
                if category == "danger" or category == "critical":
                    # Urgent Security Siren Dual-Tone
                    winsound.Beep(1200, 180)
                    time.sleep(0.05)
                    winsound.Beep(1600, 250)
                elif category == "warning":
                    winsound.Beep(800, 200)
                elif category == "success":
                    # Pleasant Connection Chime
                    winsound.Beep(600, 120)
                    time.sleep(0.05)
                    winsound.Beep(900, 150)
                else:
                    winsound.Beep(750, 100)
        except Exception:
            pass

    threading.Thread(target=_chime, daemon=True).start()
