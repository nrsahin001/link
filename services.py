import base64
import hashlib
import hmac
import re
import secrets
import smtplib
from datetime import date, datetime, timedelta
from email.message import EmailMessage

import bcrypt
from flask import current_app
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import OTPCode
from utils import utcnow

OTP_TTL = timedelta(minutes=10)
OTP_MAX_ATTEMPTS = 5
OTP_COOLDOWN_SECONDS = 60

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HANDLE_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
_PHOTO_RE = re.compile(r"^data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$")
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt()).decode()


# ---------- passwords ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed) -> bool:
    """Runs a bcrypt check even for unknown users so response time doesn't reveal them."""
    try:
        ok = bcrypt.checkpw(password.encode()[:72], (hashed or _DUMMY_HASH).encode())
    except (ValueError, TypeError):
        return False
    return ok and hashed is not None


def password_error(password: str):
    n = len(password.encode())
    if n < 8:
        return "Password must be at least 8 characters"
    if n > 72:
        return "Password is too long (max 72 bytes)"
    return None


# ---------- validation ----------
def normalize_email(value) -> str:
    return str(value or "").strip().lower()


def valid_email(email: str) -> bool:
    return len(email) <= 255 and bool(EMAIL_RE.match(email))


def parse_dob(value):
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError:
        return None


def age_on(dob: date) -> int:
    today = date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def valid_photo(value) -> bool:
    if not isinstance(value, str) or len(value) > 400_000:
        return False
    m = _PHOTO_RE.match(value)
    if not m:
        return False
    try:
        raw = base64.b64decode(m.group(2), validate=True)
    except Exception:
        return False
    kind = m.group(1)
    return (
        (kind == "jpeg" and raw[:3] == b"\xff\xd8\xff")
        or (kind == "png" and raw[:8] == b"\x89PNG\r\n\x1a\n")
        or (kind == "webp" and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP")
    )


# ---------- email ----------
def send_email(to: str, subject: str, html: str) -> bool:
    cfg = current_app.config
    msg = EmailMessage()
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(re.sub(r"<[^>]+>", " ", html))
    msg.add_alternative(html, subtype="html")
    try:
        if cfg["SMTP_SSL"]:
            smtp = smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10)
        else:
            smtp = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10)
            smtp.starttls()
        with smtp:
            smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            smtp.send_message(msg)
        return True
    except Exception:
        current_app.logger.exception("Failed to send email")
        return False


def send_otp_email(email: str, code: str, purpose: str) -> bool:
    title = "Verify your email" if purpose == "signup" else "Reset your password"
    html = (f"<h2>{title}</h2><p>Your code is: <b style='font-size:20px'>{code}</b></p>"
            f"<p>It expires in 10 minutes. If you didn't request it, ignore this email.</p>")
    return send_email(email, title, html)


# ---------- OTP ----------
def _otp_hash(email: str, purpose: str, code: str) -> str:
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{email}|{purpose}|{code}".encode(), hashlib.sha256).hexdigest()


def issue_otp(email: str, purpose: str):
    """Returns a fresh 6-digit code, or None if one was issued less than a minute ago."""
    now = utcnow()
    rec = OTPCode.query.filter_by(email=email, purpose=purpose).first()
    if rec and (now - rec.created_at).total_seconds() < OTP_COOLDOWN_SECONDS:
        return None
    code = f"{secrets.randbelow(10**6):06d}"
    if rec:
        rec.code_hash, rec.attempts = _otp_hash(email, purpose, code), 0
        rec.expires_at, rec.created_at = now + OTP_TTL, now
    else:
        db.session.add(OTPCode(email=email, purpose=purpose, code_hash=_otp_hash(email, purpose, code),
                               expires_at=now + OTP_TTL, created_at=now))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return None
    return code


def check_otp(email: str, purpose: str, code: str) -> bool:
    """Constant-time compare, max 5 guesses per code, single use."""
    rec = OTPCode.query.filter_by(email=email, purpose=purpose).with_for_update().first()
    if not rec or rec.expires_at < utcnow():
        return False
    if rec.attempts >= OTP_MAX_ATTEMPTS:
        db.session.delete(rec)
        db.session.commit()
        return False
    rec.attempts += 1
    ok = hmac.compare_digest(rec.code_hash, _otp_hash(email, purpose, str(code)))
    if ok:
        db.session.delete(rec)
    db.session.commit()
    return ok
