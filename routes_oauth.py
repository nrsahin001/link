import time
from urllib.parse import urlparse

from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from flask import Blueprint, current_app, jsonify, redirect, render_template, request, url_for

from extensions import csrf, db, limiter
from models import OAuth2Client, User, UserConsent
from oauth_server import CLIENT_AUTH_METHODS, SCOPES, build_claims, require_oauth, server
from routes_auth import current_user
from utils import safe_next

bp = Blueprint("oauth", __name__)
CORS_PATHS = {"/oauth/token", "/oauth/userinfo", "/oauth/revoke"}
_origins = {"t": 0.0, "v": set()}


def _error(message, status=400):
    return render_template("error.html", message=message), status


def _consented(user_id, client_id, scopes):
    c = UserConsent.query.filter_by(user_id=user_id, client_id=client_id).first()
    return bool(c) and set(scopes) <= set(c.scope.split())


def _save_consent(user_id, client_id, scopes):
    c = UserConsent.query.filter_by(user_id=user_id, client_id=client_id).first()
    if c:
        c.scope = " ".join(sorted(set(c.scope.split()) | set(scopes)))
    else:
        db.session.add(UserConsent(user_id=user_id, client_id=client_id, scope=" ".join(sorted(set(scopes)))))
    db.session.commit()


@bp.route("/oauth/authorize", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def authorize():
    user = current_user()
    if not user:
        return redirect(url_for("auth.login_page", next=request.full_path.rstrip("?")))
    try:
        grant = server.get_consent_grant(end_user=user)
    except OAuth2Error as e:
        return _error(e.description or e.error)

    client = grant.client
    scopes = (grant.request.scope or "").split()
    unknown = set(scopes) - set(client.scope.split())
    if unknown:
        return _error("This application requested access it is not registered for.")

    if request.method == "POST":
        if request.form.get("action") == "allow":
            _save_consent(user.id, client.client_id, scopes)
            return server.create_authorization_response(grant_user=user)
        return server.create_authorization_response(grant_user=None)  # user denied

    if client.is_first_party or _consented(user.id, client.client_id, scopes):
        return server.create_authorization_response(grant_user=user)
    return render_template("consent.html", client=client, user=user,
                           scopes=[(s, SCOPES.get(s, s)) for s in scopes])


@bp.post("/oauth/token")
@limiter.limit("60 per minute")
@csrf.exempt
def issue_token():
    return server.create_token_response()


@bp.post("/oauth/revoke")
@limiter.limit("60 per minute")
@csrf.exempt
def revoke():
    return server.create_endpoint_response("revocation")


@bp.route("/oauth/userinfo", methods=["GET", "POST"])
@limiter.limit("120 per minute")
@csrf.exempt
@require_oauth("openid")
def userinfo():
    user = db.session.get(User, current_token.user_id)
    if not user or not user.is_active:
        return jsonify(error="invalid_token"), 401
    return jsonify(build_claims(user, current_token.scope))


@bp.get("/.well-known/openid-configuration")
def discovery():
    iss = current_app.config["ISSUER"]
    return jsonify({
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "userinfo_endpoint": f"{iss}/oauth/userinfo",
        "revocation_endpoint": f"{iss}/oauth/revoke",
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": list(SCOPES),
        "token_endpoint_auth_methods_supported": CLIENT_AUTH_METHODS,
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "name", "preferred_username", "picture", "gender",
                             "email", "email_verified", "phone_number", "birthdate"],
    })


@bp.get("/.well-known/jwks.json")
def jwks():
    resp = jsonify({"keys": [current_app.config["OIDC_PUBLIC_JWK"]]})
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


# --- CORS: only for origins that belong to a registered client's redirect URIs
def _allowed_origins():
    if time.time() - _origins["t"] > 60:
        found = set()
        for c in OAuth2Client.query.all():
            for uri in c.redirect_uris:
                p = urlparse(uri)
                if p.scheme in ("http", "https") and p.netloc:
                    found.add(f"{p.scheme}://{p.netloc}")
        _origins.update(t=time.time(), v=found)
    return _origins["v"]


def init_cors(app):
    @app.after_request
    def cors(resp):
        origin = request.headers.get("Origin")
        if origin and request.path in CORS_PATHS and origin in _allowed_origins():
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Vary"] = "Origin"
        return resp
