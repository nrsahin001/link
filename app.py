import os

import click
from authlib.jose import JsonWebKey
from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from extensions import csrf, db, limiter


def _wants_json():
    return request.path.startswith(("/auth/", "/oauth/"))


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    if app.config["TRUSTED_PROXIES"]:
        n = app.config["TRUSTED_PROXIES"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    with open(app.config["OIDC_PRIVATE_KEY_PATH"], "rb") as f:
        pem = f.read()
    kid = JsonWebKey.import_key(pem, {"kty": "RSA"}).thumbprint()
    key = JsonWebKey.import_key(pem, {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256"})
    public = key.as_dict(is_private=False)
    public.update(kid=kid, use="sig", alg="RS256")
    app.config["OIDC_SIGNING_KEY"] = key   # Key object with kid -> kid is added to every ID token header
    app.config["OIDC_PUBLIC_JWK"] = public

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from oauth_server import init_oauth
    from routes_auth import bp as auth_bp
    from routes_developer import bp as developer_bp
    from routes_oauth import bp as oauth_bp, init_cors

    init_oauth(app)
    init_cors(app)
    for bp in (auth_bp, oauth_bp, developer_bp):
        app.register_blueprint(bp)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if resp.mimetype == "text/html":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        if _wants_json():
            return jsonify(success=False, message="Session expired. Refresh the page and try again."), 400
        return render_template("error.html", message="Your session expired. Go back, refresh, and try again."), 400

    @app.errorhandler(429)
    def too_many(e):
        if _wants_json():
            return jsonify(success=False, message="Too many attempts. Please wait a minute."), 429
        return render_template("error.html", message="Too many requests. Please wait a minute."), 429

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify(success=False, message="Not found"), 404
        return render_template("error.html", message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        if _wants_json():
            return jsonify(success=False, message="Something went wrong. Please try again."), 500
        return render_template("error.html", message="Something went wrong."), 500

    @app.cli.command("init-db")
    def init_db():
        """Create all tables."""
        db.create_all()
        click.echo("Database ready.")

    @app.cli.command("set-first-party")
    @click.argument("client_id")
    @click.option("--off", is_flag=True, help="Remove first-party status")
    def set_first_party(client_id, off):
        """Mark one of YOUR apps as first-party so users skip the consent screen."""
        from models import OAuth2Client
        c = OAuth2Client.query.filter_by(client_id=client_id).first()
        if not c:
            raise click.ClickException("Client not found")
        c.is_first_party = not off
        db.session.commit()
        click.echo(f"{c.client_name}: first_party={c.is_first_party}")

    return app
