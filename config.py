import os
import re
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


def _req(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _db_url():
    url = _req("DATABASE_URL")
    # Aiven's "Service URI" (postgres://...) works as-is
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg2://" + url[len(prefix):]
    return url


_SECRET = _req("SECRET_KEY")
if len(_SECRET) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters")
_DB_URL = _db_url()
_ISSUER = _req("ISSUER").rstrip("/")
_ENGINE = {"pool_pre_ping": True}
if _DB_URL.startswith("postgresql"):
    # Aiven plans cap total connections: workers x (pool_size + max_overflow) must stay under the cap.
    _ENGINE.update(pool_recycle=280, pool_size=int(os.getenv("DB_POOL_SIZE", "3")),
                   max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "2")))
    _ca = os.getenv("DB_SSL_CA")  # path to Aiven's ca.pem -> verify the server certificate
    if _ca:
        if not os.path.exists(_ca):
            raise RuntimeError(f"DB_SSL_CA file not found: {_ca}")
        _DB_URL = re.sub(r"[?&]sslmode=[^&]*", "", _DB_URL).replace("?&", "?")
        _ENGINE["connect_args"] = {"sslmode": "verify-ca", "sslrootcert": _ca}


class Config:
    SECRET_KEY = _SECRET
    ISSUER = _ISSUER
    OIDC_PRIVATE_KEY_PATH = _req("OIDC_PRIVATE_KEY_PATH")
    TRUSTED_PROXIES = int(os.getenv("TRUSTED_PROXIES", "1"))

    SQLALCHEMY_DATABASE_URI = _DB_URL
    SQLALCHEMY_ENGINE_OPTIONS = _ENGINE
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_SECURE = _ISSUER.startswith("https://")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    WTF_CSRF_TIME_LIMIT = 86400
    MAX_CONTENT_LENGTH = 1_000_000

    SMTP_HOST = _req("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = _req("SMTP_USER")
    SMTP_PASSWORD = _req("SMTP_PASSWORD")
    MAIL_FROM = os.getenv("MAIL_FROM") or _req("SMTP_USER")
    SMTP_SSL = os.getenv("SMTP_SSL", "0") == "1"

    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

    # Authlib
    OAUTH2_REFRESH_TOKEN_GENERATOR = True
    OAUTH2_TOKEN_EXPIRES_IN = {"authorization_code": 3600, "refresh_token": 3600}
