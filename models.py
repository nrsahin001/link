import hmac
import time

from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
    OAuth2TokenMixin,
)

from extensions import db
from utils import hash_secret, utcnow

REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600
BigText = db.Text()


class User(db.Model):
    """Registered accounts. Set is_active=false to block login and invalidate all tokens."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    photo = db.deferred(db.Column(BigText))
    full_name = db.Column(db.String(255), nullable=False)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.String(20))
    phone_number = db.Column(db.String(20))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    is_active = db.Column(db.Boolean, nullable=False, server_default=db.true())

    def get_user_id(self):
        return self.id


class PendingUser(db.Model):
    __tablename__ = "pending_users"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50))
    photo = db.deferred(db.Column(BigText))
    full_name = db.Column(db.String(255))
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.String(20))
    phone_number = db.Column(db.String(20))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255))
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.now(), onupdate=db.func.now())


class OTPCode(db.Model):
    """One live code per (email, purpose). Only an HMAC of the code is stored."""
    __tablename__ = "otp_codes"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (db.UniqueConstraint("email", "purpose", name="uq_otp_email_purpose"),)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    is_first_party = db.Column(db.Boolean, nullable=False, default=False)  # skips consent screen
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    owner = db.relationship("User")

    def check_client_secret(self, client_secret):
        if not self.client_secret or not client_secret:
            return False
        return hmac.compare_digest(self.client_secret, hash_secret(client_secret))


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = db.relationship("User")


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "oauth2_token"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = db.relationship("User")

    def is_refresh_token_active(self):
        if self.is_revoked():
            return False
        return self.issued_at + REFRESH_TOKEN_LIFETIME >= time.time()


class UserConsent(db.Model):
    __tablename__ = "user_consents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    client_id = db.Column(db.String(48), nullable=False)
    scope = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "client_id", name="uq_consent_user_client"),)
