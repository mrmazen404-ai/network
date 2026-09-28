# config.py
import logging
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

APP_NAME    = "Network Security Monitor"
APP_VERSION = "2.0.0"

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(BASE_DIR, "data")
DB_PATH     = os.path.join(DATA_DIR, "netsec.db")
LOG_DIR     = os.path.join(BASE_DIR, "logs")
EXPORT_DIR  = os.path.join(BASE_DIR, "exports")

os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
os.makedirs(EXPORT_DIR, mode=0o700, exist_ok=True)

# EmailJS credentials: never provide secrets as source-code defaults.
EMAILJS_SERVICE_ID  = os.getenv("NETSEC_EMAILJS_SERVICE_ID", "").strip()
EMAILJS_TEMPLATE_ID = os.getenv("NETSEC_EMAILJS_TEMPLATE_ID", "").strip()
EMAILJS_PUBLIC_KEY  = os.getenv("NETSEC_EMAILJS_PUBLIC_KEY", "").strip()
EMAILJS_PRIVATE_KEY = os.getenv("NETSEC_EMAILJS_PRIVATE_KEY", "").strip()
SESSION_TTL_SECONDS = int(os.getenv("NETSEC_SESSION_TTL_SECONDS", "28800"))
DEV_MODE = os.getenv("NETSEC_DEV_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}
SHOW_OTP_ON_EMAIL_FAILURE = (
    DEV_MODE
    and os.getenv("NETSEC_SHOW_OTP_ON_EMAIL_FAILURE", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
LOG_LEVEL = os.getenv("NETSEC_LOG_LEVEL", "INFO").upper()


def emailjs_is_configured():
    return all((
        EMAILJS_SERVICE_ID,
        EMAILJS_TEMPLATE_ID,
        EMAILJS_PUBLIC_KEY,
        EMAILJS_PRIVATE_KEY,
    ))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# Detection Thresholds
SYN_FLOOD_THRESHOLD   = int(os.getenv("NETSEC_SYN_FLOOD_THRESHOLD", "300"))   # SYN packets per 10s
DOS_PPS_THRESHOLD     = int(os.getenv("NETSEC_DOS_PPS_THRESHOLD", "3500"))  # Packets/second
ARP_CACHE_TIMEOUT     = int(os.getenv("NETSEC_ARP_CACHE_TIMEOUT", "300"))   # Seconds
PORT_SCAN_TIMEOUT     = 0.5
SCAN_SUBNET_TIMEOUT   = 3
OFFLINE_FAILURE_THRESHOLD = 3 # Device must miss 3 consecutive scans (45s) before marked offline

# Database Retention Settings
DB_MAX_PACKET_RECORDS = int(os.getenv("NETSEC_DB_MAX_PACKET_RECORDS", "10000"))
DB_RETENTION_DAYS     = int(os.getenv("NETSEC_DB_RETENTION_DAYS", "7"))

# Real-Time Notification Settings
ENABLE_TOAST_NOTIFICATIONS = True
ENABLE_TRAY_NOTIFICATIONS  = True
ENABLE_AUDIO_ALERTS        = True
TOAST_DISPLAY_DURATION_MS  = 5000

# Theme Palettes
THEMES = {
    "Cyberpunk": {
        "bg":          "#0b0e14",
        "panel":       "#131822",
        "panel_hover": "#1c2333",
        "border":      "#263248",
        "text":        "#dbe6f6",
        "text_sub":    "#8295b3",
        "accent":      "#00e5ff",
        "accent_hover":"#00b0ff",
        "success":     "#00e676",
        "warning":     "#ffea00",
        "danger":      "#ff1744",
        "card_bg":     "#161d2b",
    },
    "Deep Blue": {
        "bg":          "#0f172a",
        "panel":       "#1e293b",
        "panel_hover": "#334155",
        "border":      "#334155",
        "text":        "#f8fafc",
        "text_sub":    "#94a3b8",
        "accent":      "#38bdf8",
        "accent_hover":"#0284c7",
        "success":     "#22c55e",
        "warning":     "#eab308",
        "danger":      "#ef4444",
        "card_bg":     "#1e293b",
    },
    "Clean Light": {
        "bg":          "#f8fafc",
        "panel":       "#ffffff",
        "panel_hover": "#f1f5f9",
        "border":      "#e2e8f0",
        "text":        "#0f172a",
        "text_sub":    "#64748b",
        "accent":      "#0284c7",
        "accent_hover":"#0369a1",
        "success":     "#16a34a",
        "warning":     "#ca8a04",
        "danger":      "#dc2626",
        "card_bg":     "#f1f5f9",
    }
}

CURRENT_THEME = "Cyberpunk"

def set_current_theme(theme_name):
    global CURRENT_THEME
    if theme_name in THEMES:
        CURRENT_THEME = theme_name

def get_colors():
    return THEMES.get(CURRENT_THEME, THEMES["Cyberpunk"])

def get_app_stylesheet(theme_name="Cyberpunk"):
    set_current_theme(theme_name)
    c = get_colors()
    return f"""
    QMainWindow, QWidget {{
        background-color: {c['bg']};
        color: {c['text']};
        font-family: 'Segoe UI', Arial, sans-serif;
    }}
    QLabel {{
        background-color: transparent;
        border: none;
        padding: 0px;
    }}
    QFrame#PanelFrame {{
        background-color: {c['panel']};
        border: 1px solid {c['border']};
        border-radius: 8px;
    }}
    QPushButton {{
        background-color: {c['accent']};
        color: #ffffff;
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: {c['accent_hover']};
    }}
    QPushButton:disabled {{
        background-color: {c['border']};
        color: {c['text_sub']};
    }}
    QTableWidget {{
        background-color: {c['panel']};
        color: {c['text']};
        gridline-color: {c['border']};
        border: 1px solid {c['border']};
        border-radius: 6px;
    }}
    QHeaderView::section {{
        background-color: {c['bg']};
        color: {c['accent']};
        font-weight: bold;
        padding: 8px;
        border: 1px solid {c['border']};
    }}
    QLineEdit, QPlainTextEdit {{
        background-color: {c['bg']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 6px;
        padding: 6px;
    }}
    QProgressBar {{
        border: 1px solid {c['border']};
        border-radius: 6px;
        text-align: center;
        color: {c['text']};
        background-color: {c['bg']};
    }}
    QProgressBar::chunk {{
        background-color: {c['accent']};
        border-radius: 5px;
    }}
    """
