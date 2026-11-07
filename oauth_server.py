from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import (
    create_bearer_token_validator,
    create_query_client_func,
    create_revocation_endpoint,
    create_save_token_func,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from flask import current_app

from extensions import db
from models import OAuth2AuthorizationCode, OAuth2Client, OAuth2Token, User
from utils import avatar_url, utcnow
import time

SCOPES = {
    "openid": "Verify who you are",
    "profile": "Your name, user ID, photo and gender",
    "email": "Your email address",
    "phone": "Your phone number",
    "birthdate": "Your date of birth",
}
CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

server = AuthorizationServer()
require_oauth = ResourceProtector()


def build_claims(user, scope):
    scopes = set(scope.split()) if isinstance(scope, str) else set(scope or [])
    claims = {"sub": str(user.id)}
    if "profile" in scopes:
        claims.update(name=user.full_name, preferred_username=user.user_id, gender=user.gender)
        if user.photo:
            claims["picture"] = avatar_url(user)
    if "email" in scopes:
        claims.update(email=user.email, email_verified=True)
    if "phone" in scopes and user.phone_number:
        claims["phone_number"] = user.phone_number
    if "birthdate" in scopes and user.date_of_birth:
        claims["birthdate"] = user.date_of_birth.isoformat()
    return claims


class PKCE(CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]  # no "plain"


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = CLIENT_AUTH_METHODS

    def save_authorization_code(self, code, request):
        db.session.add(OAuth2AuthorizationCode(
            code=code, client_id=request.client.client_id, redirect_uri=request.redirect_uri,
            scope=request.scope, user_id=request.user.id, nonce=request.data.get("nonce"),
            code_challenge=request.data.get("code_challenge"),
            code_challenge_method=request.data.get("code_challenge_method"),
        ))
        db.session.commit()

    def query_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        user = db.session.get(User, authorization_code.user_id)
        return user if user and user.is_active else None


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return OAuth2AuthorizationCode.query.filter_by(
            client_id=request.client_id, nonce=nonce).first() is not None

    def get_jwt_config(self, grant):
        return {"key": current_app.config["OIDC_SIGNING_KEY"], "alg": "RS256",
                "iss": current_app.config["ISSUER"], "exp": 3600}

    def generate_user_info(self, user, scope):
        return UserInfo(build_claims(user, scope))


class RefreshTokenGrant(grants.RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = CLIENT_AUTH_METHODS
    INCLUDE_NEW_REFRESH_TOKEN = True  # rotation: every refresh issues a new refresh token

    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        user = db.session.get(User, credential.user_id)
        return user if user and user.is_active else None

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.add(credential)
        db.session.commit()


_Revocation = create_revocation_endpoint(db.session, OAuth2Token)


class RevocationEndpoint(_Revocation):
    CLIENT_AUTH_METHODS = CLIENT_AUTH_METHODS


BearerTokenValidator = create_bearer_token_validator(db.session, OAuth2Token)


def init_oauth(app):
    app.config["OAUTH2_SCOPES_SUPPORTED"] = list(SCOPES)
    server.init_app(
        app,
        query_client=create_query_client_func(db.session, OAuth2Client),
        save_token=create_save_token_func(db.session, OAuth2Token),
    )
    server.register_grant(AuthorizationCodeGrant, [PKCE(required=True), OpenIDCode(require_nonce=False)])
    server.register_grant(RefreshTokenGrant)
    server.register_endpoint(RevocationEndpoint)
    require_oauth.register_token_validator(BearerTokenValidator())
