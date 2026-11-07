import base64
import hmac
import time
from functools import wraps

from flask import (Blueprint, Response, abort, jsonify, redirect, render_template,
                   request, session, url_for)
from sqlalchemy.exc import IntegrityError

from extensions import db, limiter
from models import OAuth2Client, OAuth2Token, PendingUser, User, UserConsent
from services import (HANDLE_RE, age_on, check_otp, hash_password, issue_otp, normalize_email,
                      parse_dob, password_error, send_otp_email, valid_email, valid_photo,
                      verify_password)
from utils import avatar_sig, avatar_url, safe_next

bp = Blueprint("auth", __name__)


def fail(message, status=400):
    return jsonify(success=False, message=message), status


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    user = db.session.get(User, uid)
    if not user or not user.is_active:
        session.clear()
        return None
    return user


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("auth.login_page", next=request.full_path.rstrip("?")))
        return view(*a, **kw)
    return wrapper


def _email_key():
    data = request.get_json(silent=True)
    email = data.get("email", "") if isinstance(data, dict) else ""
    return "email:" + str(email).strip().lower()[:255]


def revoke_all_tokens(user_id, client_id=None):
    now = int(time.time())
    q = OAuth2Token.query.filter_by(user_id=user_id)
    if client_id:
        q = q.filter_by(client_id=client_id)
    q.update({"access_token_revoked_at": now, "refresh_token_revoked_at": now})


# ------------------------------------------------------------------ pages
@bp.get("/")
def index():
    return redirect(url_for("auth.account" if current_user() else "auth.login_page"))


@bp.get("/login")
def login_page():
    nxt = safe_next(request.args.get("next"))
    if current_user():
        return redirect(nxt or url_for("auth.account"))
    return render_template("login.html", next=nxt or "")


@bp.get("/signup")
def signup_page():
    return render_template("signup.html", next=safe_next(request.args.get("next")) or "")


@bp.get("/forgot")
def forgot_page():
    return render_template("forgot.html")


@bp.get("/account")
@login_required
def account():
    user = current_user()
    apps = (db.session.query(UserConsent, OAuth2Client)
            .join(OAuth2Client, OAuth2Client.client_id == UserConsent.client_id)
            .filter(UserConsent.user_id == user.id).all())
    photo = avatar_url(user) if user.photo else None
    return render_template("account.html", user=user, apps=apps, photo=photo)


@bp.get("/avatar/<int:uid>/<sig>")
def avatar(uid, sig):
    if not hmac.compare_digest(sig, avatar_sig(uid)):
        abort(404)
    user = db.session.get(User, uid)
    if not user or not user.photo:
        abort(404)
    header, b64 = user.photo.split(",", 1)
    mime = header[5:].split(";")[0]
    return Response(base64.b64decode(b64), mimetype=mime, headers={
        "Cache-Control": "public, max-age=3600", "Content-Security-Policy": "default-src 'none'"})


# ------------------------------------------------------------------ API
@bp.post("/auth/signup")
@limiter.limit("5 per minute;30 per hour")
def signup():
    d = request.get_json(silent=True) or {}
    full_name = str(d.get("fullName", "")).strip()
    handle = str(d.get("user_id", "")).strip().lstrip("#")
    gender = str(d.get("gender", "")).lower()
    phone = str(d.get("phone") or "").strip()
    email = normalize_email(d.get("email"))
    password = str(d.get("password", ""))
    photo = d.get("photo") or None
    dob = parse_dob(d.get("age"))

    if not 2 <= len(full_name) <= 100:
        return fail("Please enter your full name")
    if not HANDLE_RE.match(handle):
        return fail("User ID must be 1-8 letters or digits")
    if not dob or not 18 <= age_on(dob) <= 120:
        return fail("You must be 18 or older")
    if gender not in ("male", "female", "other"):
        return fail("Please select a gender")
    if phone and not (phone.isdigit() and len(phone) == 10):
        return fail("Phone number must be 10 digits")
    if not valid_email(email):
        return fail("Invalid email address")
    if password_error(password):
        return fail(password_error(password))
    if photo and not valid_photo(photo):
        return fail("Invalid or too large photo")

    user_id = "#" + handle
    if User.query.filter_by(email=email).first():
        return fail("Email already registered", 409)
    if User.query.filter_by(user_id=user_id).first():
        return fail("That user ID is already taken", 409)

    PendingUser.query.filter_by(email=email).delete()
    db.session.add(PendingUser(user_id=user_id, photo=photo, full_name=full_name, date_of_birth=dob,
                               gender=gender, phone_number=phone or None, email=email,
                               password=hash_password(password)))
    db.session.commit()

    code = issue_otp(email, "signup")
    if code is None:
        return jsonify(success=True, message="A code was sent recently. Check your inbox.")
    if not send_otp_email(email, code, "signup"):
        return fail("Could not send the verification email. Try again shortly.", 502)
    return jsonify(success=True, message="Verification code sent")


@bp.post("/auth/signup/verify")
@limiter.limit("10 per minute")
@limiter.limit("10 per minute", key_func=_email_key)
def signup_verify():
    d = request.get_json(silent=True) or {}
    email, code = normalize_email(d.get("email")), str(d.get("otp", "")).strip()
    if not check_otp(email, "signup", code):
        return fail("Invalid or expired code")
    p = PendingUser.query.filter_by(email=email).first()
    if not p:
        return fail("Signup expired. Please start again.", 404)
    db.session.add(User(user_id=p.user_id, photo=p.photo, full_name=p.full_name,
                        date_of_birth=p.date_of_birth, gender=p.gender,
                        phone_number=p.phone_number, email=p.email, password=p.password))
    db.session.delete(p)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return fail("That user ID or email was just taken. Start again.", 409)
    return jsonify(success=True, message="Account created. You can sign in now.")


@bp.post("/auth/signup/resend")
@limiter.limit("5 per minute")
@limiter.limit("5 per minute", key_func=_email_key)
def signup_resend():
    email = normalize_email((request.get_json(silent=True) or {}).get("email"))
    if PendingUser.query.filter_by(email=email).first():
        code = issue_otp(email, "signup")
        if code and not send_otp_email(email, code, "signup"):
            return fail("Could not send email", 502)
    return jsonify(success=True, message="If a signup is pending, a new code was sent.")


@bp.post("/auth/login")
@limiter.limit("20 per minute")
@limiter.limit("5 per minute", key_func=_email_key)
def login():
    d = request.get_json(silent=True) or {}
    email, password = normalize_email(d.get("email")), str(d.get("password", ""))
    user = User.query.filter_by(email=email).first()
    ok = verify_password(password, user.password if user else None)
    if not (user and ok and user.is_active):
        return fail("Invalid email or password", 401)
    session.clear()
    session.permanent = True
    session["uid"] = user.id
    return jsonify(success=True, redirect=safe_next(d.get("next")) or url_for("auth.account"))


@bp.post("/auth/forgot/request")
@limiter.limit("5 per minute")
@limiter.limit("3 per minute", key_func=_email_key)
def forgot_request():
    email = normalize_email((request.get_json(silent=True) or {}).get("email"))
    user = User.query.filter_by(email=email).first()
    if user and user.is_active:
        code = issue_otp(email, "reset")
        if code:
            send_otp_email(email, code, "reset")
    # identical response whether or not the account exists (no user enumeration)
    return jsonify(success=True, message="If that email is registered, a code has been sent.")


@bp.post("/auth/forgot/reset")
@limiter.limit("10 per minute")
@limiter.limit("10 per minute", key_func=_email_key)
def forgot_reset():
    d = request.get_json(silent=True) or {}
    email, code, password = normalize_email(d.get("email")), str(d.get("otp", "")).strip(), str(d.get("password", ""))
    if password_error(password):
        return fail(password_error(password))
    user = User.query.filter_by(email=email).first()
    if not user or not check_otp(email, "reset", code):
        return fail("Invalid or expired code")
    user.password = hash_password(password)
    revoke_all_tokens(user.id)  # sign out every connected app
    db.session.commit()
    return jsonify(success=True, message="Password updated")


@bp.post("/auth/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login_page"))


@bp.post("/auth/consents/<int:consent_id>/revoke")
@login_required
def revoke_consent(consent_id):
    user = current_user()
    c = UserConsent.query.filter_by(id=consent_id, user_id=user.id).first_or_404()
    revoke_all_tokens(user.id, c.client_id)
    db.session.delete(c)
    db.session.commit()
    return redirect(url_for("auth.account"))
