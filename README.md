# Central Auth Server (OAuth 2.0 + OpenID Connect)

Signup, sign-in and password reset with email codes, exposed as a "Sign in with …" identity provider for
all of your apps and for third-party developers.

## Setup (fresh install, Aiven PostgreSQL)
1. In the Aiven console open your PostgreSQL service, copy the **Service URI**, download the **CA certificate**
   and save it as `certs/aiven-ca.pem`.
2. ```bash
   python -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env            # fill in SECRET_KEY, ISSUER, DATABASE_URL, SMTP_*
   python scripts/gen_keys.py      # creates keys/oidc_private.pem (back it up, never commit it)
   flask --app wsgi init-db        # creates all tables
   gunicorn wsgi:app -b 127.0.0.1:8000 -w 3
   ```
3. Put nginx/Caddy in front with HTTPS, forward `X-Forwarded-For/Proto/Host`, and set `TRUSTED_PROXIES=1`.
4. Each gunicorn worker holds up to `DB_POOL_SIZE + DB_MAX_OVERFLOW` connections (default 3 + 2); with `-w 3`
   that is at most 15. Check your Aiven plan's connection limit.

`python tests/test_flow.py` runs the end-to-end test (needs a key at /tmp/testkey.pem; set `TEST_DATABASE_URL`
to test against PostgreSQL, otherwise it uses SQLite).

## For developers integrating
1. Sign up at `https://auth.example.com/signup`, open `/developer`, register an app (redirect URIs, scopes).
2. Point any OIDC library at `https://auth.example.com/.well-known/openid-configuration`.
3. Use Authorization Code + PKCE (S256 is mandatory). See `demo_client/app.py`.

| Endpoint | Purpose |
|---|---|
| `GET /oauth/authorize` | login + consent |
| `POST /oauth/token` | code / refresh token exchange |
| `GET /oauth/userinfo` | profile claims for a Bearer token |
| `POST /oauth/revoke` | revoke access/refresh token |
| `GET /.well-known/openid-configuration`, `/.well-known/jwks.json` | discovery + ID-token keys |

Scopes: `openid`, `profile` (name, user ID, photo, gender), `email`, `phone`, `birthdate`.
Access tokens: opaque, 1 hour. Refresh tokens: 30 days, rotated on every use. ID tokens: RS256 JWT.

## Operations
- Mark your own apps first-party (no consent screen): `flask --app wsgi set-first-party <client_id>`
- Deactivate a user: `UPDATE users SET is_active=0 WHERE email='…'` (blocks login and all tokens).
- Rate limiting needs Redis when running several workers: `RATELIMIT_STORAGE_URI=redis://…`.
- `AUTHLIB_INSECURE_TRANSPORT=1` is for local HTTP testing only; never set it in production.
