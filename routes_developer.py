import re
import secrets
import time
from urllib.parse import urlparse

from flask import Blueprint, current_app, render_template, request
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin  # noqa: F401

from extensions import db, limiter
from models import OAuth2AuthorizationCode, OAuth2Client, OAuth2Token, UserConsent
from oauth_server import SCOPES
from routes_auth import current_user, login_required
from utils import hash_secret

bp = Blueprint("developer", __name__)
MAX_CLIENTS = 10
_NATIVE_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+$")  # reverse-DNS, e.g. com.acme.app


def valid_redirect_uri(uri: str) -> bool:
    if len(uri) > 2000 or "*" in uri:
        return False
    p = urlparse(uri)
    if p.fragment:
        return False
    if p.scheme == "https":
        return bool(p.netloc)
    if p.scheme == "http":
        return p.hostname in ("localhost", "127.0.0.1", "::1")
    return bool(_NATIVE_SCHEME.match(p.scheme))


def _render(user, errors=None, new_secret=None, new_client=None, status=200):
    clients = OAuth2Client.query.filter_by(owner_id=user.id).order_by(OAuth2Client.id.desc()).all()
    return render_template("developer.html", user=user, clients=clients, scopes=SCOPES, errors=errors or [],
                           new_secret=new_secret, new_client=new_client,
                           issuer=current_app.config["ISSUER"]), status


@bp.get("/developer")
@login_required
def portal():
    return _render(current_user())


@bp.post("/developer/clients")
@login_required
@limiter.limit("20 per hour")
def create_client():
    user = current_user()
    name = request.form.get("name", "").strip()
    kind = request.form.get("type", "confidential")
    uris = list(dict.fromkeys(u.strip() for u in request.form.get("redirect_uris", "").splitlines() if u.strip()))
    scopes = [s for s in request.form.getlist("scopes") if s in SCOPES]
    if "openid" not in scopes:
        scopes.insert(0, "openid")

    errors = []
    if not 2 <= len(name) <= 80:
        errors.append("App name must be 2-80 characters.")
    if kind not in ("confidential", "public"):
        errors.append("Invalid app type.")
    if not uris or len(uris) > 10:
        errors.append("Provide between 1 and 10 redirect URIs.")
    errors += [f"Invalid redirect URI: {u} (use https, or http://localhost for development)"
               for u in uris if not valid_redirect_uri(u)]
    if OAuth2Client.query.filter_by(owner_id=user.id).count() >= MAX_CLIENTS:
        errors.append(f"You can register at most {MAX_CLIENTS} apps.")
    if errors:
        return _render(user, errors, status=400)

    client = OAuth2Client(owner_id=user.id, client_id=secrets.token_urlsafe(24),
                          client_id_issued_at=int(time.time()), client_secret="")
    secret = None
    if kind == "confidential":
        secret = secrets.token_urlsafe(40)
        client.client_secret = hash_secret(secret)
    client.set_client_metadata({
        "client_name": name, "redirect_uris": uris, "scope": " ".join(scopes),
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic" if secret else "none",
    })
    db.session.add(client)
    db.session.commit()
    return _render(user, new_secret=secret, new_client=client, status=201)


@bp.post("/developer/clients/<int:cid>/rotate")
@login_required
def rotate_secret(cid):
    user = current_user()
    client = OAuth2Client.query.filter_by(id=cid, owner_id=user.id).first_or_404()
    if client.token_endpoint_auth_method == "none":
        return _render(user, ["Public clients have no secret."], status=400)
    secret = secrets.token_urlsafe(40)
    client.client_secret = hash_secret(secret)
    db.session.commit()
    return _render(user, new_secret=secret, new_client=client)


@bp.post("/developer/clients/<int:cid>/delete")
@login_required
def delete_client(cid):
    user = current_user()
    client = OAuth2Client.query.filter_by(id=cid, owner_id=user.id).first_or_404()
    for model in (OAuth2Token, OAuth2AuthorizationCode, UserConsent):
        model.query.filter_by(client_id=client.client_id).delete()
    db.session.delete(client)
    db.session.commit()
    return _render(user)
