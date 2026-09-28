# core/email_service.py
import logging
import secrets
import string
import re
import requests

from config import (
    EMAILJS_PRIVATE_KEY,
    EMAILJS_PUBLIC_KEY,
    EMAILJS_SERVICE_ID,
    EMAILJS_TEMPLATE_ID,
    emailjs_is_configured,
)

logger = logging.getLogger(__name__)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def generate_6char_otp():
    """Generate a cryptographically secure, readable six-character OTP."""
    alphabet = string.ascii_uppercase + string.digits
    clean_chars = alphabet.replace("0", "").replace("O", "").replace("1", "").replace("I", "")
    return "".join(secrets.choice(clean_chars) for _ in range(6))


def send_emailjs_otp(to_email, user_name, otp_code, purpose="verification"):
    """Send an OTP code via EmailJS REST API."""
    if not EMAIL_RE.fullmatch(to_email.strip()):
        return False, "Invalid recipient email address."
    if len(otp_code) != 6:
        return False, "Invalid OTP value."
    if not emailjs_is_configured():
        logger.error("EmailJS is not configured; OTP delivery is unavailable")
        return False, "Email verification service is not configured."

    purpose_label = {
        "registration": "Email verification",
        "password_reset": "Password recovery",
    }.get(purpose, "Security verification")
    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_PUBLIC_KEY,
        "accessToken": EMAILJS_PRIVATE_KEY,
        "template_params": {
            "reply_to": to_email,
            "to_email": to_email,
            "email": to_email,
            "user_email": to_email,
            "recipient": to_email,
            "email_to": to_email,
            "send_to": to_email,
            "to_name": user_name,
            "user_name": user_name,
            "otp_code": otp_code,
            "passcode": otp_code,
            "code": otp_code,
            "purpose": purpose,
            "purpose_label": purpose_label,
            "expires_minutes": "10",
            "app_name": "Network Security Monitor",
            "message": f"Your 6-character Network Security Monitor verification code is: {otp_code}",
        },
    }
    try:
        response = requests.post(
            "https://api.emailjs.com/api/v1.0/email/send",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if response.status_code == 200 and response.text.strip().upper() == "OK":
            return True, "Verification email successfully dispatched."
        logger.warning("Email provider rejected OTP request with status %s", response.status_code)
        return False, "Email provider rejected the message."
    except requests.RequestException:
        logger.exception("Email provider request failed.")
        return False, "Unable to reach email service."
