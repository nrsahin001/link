import hashlib
import hmac
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import current_app


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_secret(secret: str) -> str:
    """Client secrets are high-entropy random strings, so a plain SHA-256 is appropriate."""
    return hashlib.sha256(secret.encode()).hexdigest()


def avatar_sig(uid: int) -> str:
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"avatar:{uid}".encode(), hashlib.sha256).hexdigest()[:24]


def avatar_url(user) -> str:
    return f"{current_app.config['ISSUER']}/avatar/{user.id}/{avatar_sig(user.id)}"


def safe_next(target):
    """Only allow same-site relative paths (prevents open redirects)."""
    if not target or not isinstance(target, str):
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    return target
