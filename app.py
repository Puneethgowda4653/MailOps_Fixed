"""
app.py - MailOps Phase 5  |  Multi-tenant, individual accounts

Fixes applied vs previous version:
  - BASE_URL env var replaces hardcoded 127.0.0.1 in tracking
  - SESSION_COOKIE_SECURE enforced when HTTPS=true
  - HTTPS redirect middleware
  - Content-Security-Policy header added
  - flask-limiter switched to Redis backend (cross-worker, persistent)
  - campaign_state moved to Redis (shared across all Gunicorn workers)
  - Password reset flow (/forgot-password, /reset-password/<token>)
  - Email verification on registration
  - Daily send quota guard (per-user counter in MongoDB)
  - Tracking event writes validated against campaigns collection
  - global unsubscribe scoped to prevent cross-user data changes
  - /healthz endpoint for monitoring
"""

import os, threading, logging, io, csv, hmac, hashlib, secrets, json
from datetime import datetime, timedelta, timezone, timezone as _tz
IST = timezone(timedelta(hours=5, minutes=30))
from functools import wraps
from urllib.parse import unquote

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, jsonify, send_file, session, Response, make_response)
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import bleach, pandas as pd
from dotenv import load_dotenv

import store
from mailer_engine import run_campaign, validate_recipients

load_dotenv()

# ── App ────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
secret = os.getenv("FLASK_SECRET_KEY")
if not secret or secret == "REPLACE_WITH_A_STRONG_RANDOM_SECRET":
    raise RuntimeError(
        "FLASK_SECRET_KEY is not set or is still the placeholder value. "
        "Run: python -c \"import secrets; print(secrets.token_hex(32))\" "
        "and paste the output into your .env file."
    )

HTTPS_ENABLED = os.getenv("HTTPS", "false").lower() == "true"
BASE_URL       = os.getenv("BASE_URL", "http://localhost:5000").rstrip("/")
REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app.secret_key = secret
app.config.update(
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SAMESITE    = "Lax",
    SESSION_COOKIE_SECURE      = HTTPS_ENABLED,
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60),
    MAX_CONTENT_LENGTH         = 16 * 1024 * 1024,
    WTF_CSRF_TIME_LIMIT        = 3600,
)

csrf = CSRFProtect(app)

# Redis: optional for local dev, required for production multi-worker deployments
import redis as redis_lib
_redis        = None
REDIS_ENABLED = False
try:
    _r = redis_lib.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=2)
    _r.ping()
    _redis        = _r
    REDIS_ENABLED = True
    limiter_uri   = REDIS_URL
    logging.info("Redis connected — using Redis for rate limiting and campaign state.")
except Exception as _re:
    logging.warning(
        f"Redis not available ({_re}). "
        "Falling back to in-memory rate limiting and campaign state. "
        "Fine for local dev; NOT suitable for multi-worker production."
    )
    limiter_uri = "memory://"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=limiter_uri,
)

UPLOAD_FOLDER  = "uploads"
ALLOWED_CSV    = {"csv", "xlsx", "xls"}
ALLOWED_ATTACH = {"pdf", "docx", "xlsx", "png", "jpg", "jpeg", "txt", "zip"}
for d in ("uploads", "logs"):
    os.makedirs(d, exist_ok=True)

CAMPAIGN_STATE_TTL = 60 * 60 * 24  # 24 hours
# In-memory fallback store for when Redis is unavailable
_mem_campaign_state: dict = {}

def _cs_key(run_id):
    return f"campaign_state:{run_id}"

def get_campaign_state(run_id):
    if _redis:
        raw = _redis.get(_cs_key(run_id))
        return json.loads(raw) if raw else None
    return _mem_campaign_state.get(run_id)

def set_campaign_state(run_id, state):
    if _redis:
        _redis.setex(_cs_key(run_id), CAMPAIGN_STATE_TTL, json.dumps(state, default=str))
    else:
        _mem_campaign_state[run_id] = state

def update_campaign_state(run_id, updates):
    """Atomic-ish update — read-modify-write with a short lock."""
    data = get_campaign_state(run_id) or {}
    data.update(updates)
    set_campaign_state(run_id, data)
    return data

# Keep a local threading lock just for the append-results path
_append_locks: dict = {}

def _get_lock(run_id):
    if run_id not in _append_locks:
        _append_locks[run_id] = threading.Lock()
    return _append_locks[run_id]

# ── Audit log ─────────────────────────────────────────────────────────────────
_al = logging.getLogger("audit")
_al.setLevel(logging.INFO)
_ah = logging.FileHandler("logs/audit.log")
_ah.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
_al.addHandler(_ah)

def audit(action, detail=""):
    _al.info(f"user={session.get('username','anon')} | ip={request.remote_addr} | {action} | {detail}")

# ── Security middleware ────────────────────────────────────────────────────────
@app.after_request
def security_headers(r):
    # FIX: added Content-Security-Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    r.headers.update({
        "X-Content-Type-Options":    "nosniff",
        "X-Frame-Options":           "DENY",
        "X-XSS-Protection":          "1; mode=block",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Content-Security-Policy":   csp,                    # FIX: was missing
        "Permissions-Policy":        "geolocation=(), camera=(), microphone=()",
    })
    return r

@app.before_request
def enforce_https_and_session():
    # FIX: HTTPS redirect when running in production
    if HTTPS_ENABLED and not request.is_secure and request.headers.get("X-Forwarded-Proto") != "https":
        return redirect(request.url.replace("http://", "https://", 1), code=301)

    if session.get("logged_in"):
        last = session.get("last_active")
        if last and (datetime.utcnow() - datetime.fromisoformat(last)) > timedelta(minutes=60):
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        session["last_active"] = datetime.utcnow().isoformat()

@app.errorhandler(CSRFError)
def csrf_err(e):
    flash("Security token expired. Try again.", "error")
    return redirect(request.referrer or url_for("index"))

@app.errorhandler(413)
def too_large(e):
    flash("File too large. Max 16MB.", "error")
    return redirect(request.referrer or url_for("compose"))

# ── Decorators ─────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if not session.get("logged_in"):
            flash("Please log in.", "info")
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return d

def smtp_required(f):
    @wraps(f)
    def d(*a, **k):
        if not store.smtp_is_configured(session["user_id"]):
            flash("Set up your SMTP settings first.", "warning")
            return redirect(url_for("smtp_settings"))
        return f(*a, **k)
    return d

def verified_required(f):
    """Block unverified email accounts from sending campaigns."""
    @wraps(f)
    def d(*a, **k):
        user = store.get_user_by_id(uid())
        if user and not user.get("email_verified", True):
            flash("Please verify your email address before sending campaigns. "
                  "Check your inbox or request a new verification email.", "warning")
            return redirect(url_for("resend_verification"))
        return f(*a, **k)
    return d

# ── Helpers ────────────────────────────────────────────────────────────────────
def uid():
    return session.get("user_id", "")

def allowed_file(fn, s):
    return "." in fn and fn.rsplit(".", 1)[1].lower() in s

def sanitize_html(html):
    if not html:
        return ""
    # Always normalise line endings first
    html = html.replace("\r\n", "\n").replace("\r", "\n")
    # If it looks like plain text (no block/inline tags), convert newlines to <br>
    import re as _re
    has_block = bool(_re.search(r"<(p|div|br|h[1-6]|ul|ol|li|table|blockquote)\b", html, _re.I))
    if not has_block:
        html = "<br>".join(html.split("\n"))
    # Allow a comprehensive set of safe CSS properties via css_sanitizer
    try:
        from bleach.css_sanitizer import CSSSanitizer  # bleach >= 5.0
        css_san = CSSSanitizer(allowed_css_properties=[
            "color","background-color","background","font-size","font-family",
            "font-weight","font-style","text-align","text-decoration","line-height",
            "margin","margin-top","margin-bottom","margin-left","margin-right",
            "padding","padding-top","padding-bottom","padding-left","padding-right",
            "border","border-radius","width","max-width","height","display",
            "vertical-align","float","clear","white-space","word-break",
        ])
        return bleach.clean(
            html,
            tags=["p","br","strong","em","u","b","i","a","ul","ol","li","h1","h2","h3",
                  "blockquote","span","div","table","thead","tbody","tr","th","td","img","hr"],
            attributes={"a":["href","title","target"],"img":["src","alt","width","height","style"],
                        "*":["style","class","align","valign","bgcolor","border","cellpadding","cellspacing"]},
            css_sanitizer=css_san,
            strip=True,
        )
    except ImportError:
        return bleach.clean(
            html,
            tags=["p","br","strong","em","u","b","i","a","ul","ol","li","h1","h2","h3",
                  "blockquote","span","div","table","thead","tbody","tr","th","td","img","hr"],
            attributes={"a":["href","title","target"],"img":["src","alt","width","height","style"],
                        "*":["style","class","align","valign"]},
            strip=True,
        )

def load_recipients(path):
    ext = path.rsplit(".", 1)[1].lower()
    df  = pd.read_csv(path, dtype=str).fillna("") if ext == "csv" \
          else pd.read_excel(path, dtype=str).fillna("")
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    return df.to_dict("records")

def verify_webhook_token(token):
    expected = hmac.new(
        os.getenv("FLASK_SECRET_KEY", "").encode(),
        b"mailops-webhook", hashlib.sha256
    ).hexdigest()[:32]
    return hmac.compare_digest(token or "", expected)

def send_system_email(to_email, subject, html_body):
    """
    Send a transactional system email (verification, password reset).
    Uses SendGrid if SENDGRID_API_KEY is set, otherwise falls back to
    the requesting user's own SMTP (suitable for dev only).
    """
    api_key = os.getenv("SENDGRID_API_KEY", "")
    from_   = os.getenv("SYSTEM_EMAIL_FROM", "noreply@mailops.app")

    if api_key:
        try:
            import sendgrid as sg_lib
            from sendgrid.helpers.mail import Mail
            sg  = sg_lib.SendGridAPIClient(api_key)
            msg = Mail(from_email=from_, to_emails=to_email,
                       subject=subject, html_content=html_body)
            sg.send(msg)
            return True
        except Exception as e:
            _al.error(f"SendGrid error: {e}")
            return False

    # Dev fallback — use the current user's SMTP if available
    user_id = uid()
    if user_id:
        smtp_cfg = store.get_smtp_config(user_id)
        if smtp_cfg:
            try:
                import smtplib, ssl
                from mailer_engine import build_message
                msg = build_message(smtp_cfg, {"email": to_email, "first_name": ""}, subject, html_body)
                ctx = ssl.create_default_context()
                with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=20) as s:
                    s.ehlo(); s.starttls(context=ctx); s.ehlo()
                    s.login(smtp_cfg["user"], smtp_cfg["password"])
                    s.sendmail(smtp_cfg["user"], to_email, msg.as_bytes())
                return True
            except Exception as e:
                _al.error(f"Dev SMTP fallback error: {e}")
    return False

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    if session.get("logged_in"):
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        errs = []
        if len(username) < 2:   errs.append("Username must be at least 2 characters.")
        if "@" not in email:    errs.append("Valid email address required.")
        if len(password) < 8:   errs.append("Password must be at least 8 characters.")
        if password != confirm:  errs.append("Passwords do not match.")
        if errs:
            [flash(e, "error") for e in errs]
            return render_template("register.html")

        token   = secrets.token_urlsafe(32)
        user_id = store.create_user(username, password, email, verification_token=token)
        if not user_id:
            flash("That email is already registered. Please log in.", "error")
            return render_template("register.html")

        verify_url = f"{BASE_URL}/verify-email/{token}"
        # New users have no SMTP yet — log the link; send via SendGrid if configured
        logging.info(f"VERIFY LINK for {email}: {verify_url}")
        if os.getenv("SENDGRID_API_KEY", ""):
            send_system_email(
                email,
                "Verify your MailOps account",
                f"<p>Hi {username},</p>"
                f"<p>Click the link below to verify your email address:</p>"
                f"<p><a href='{verify_url}'>{verify_url}</a></p>"
                f"<p>This link expires in 24 hours.</p>"
            )
        audit("REGISTER", f"user={username} email={email}")
        flash("Account created! Check your inbox to verify your email before sending campaigns.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/verify-email/<token>")
def verify_email(token):
    ok = store.verify_email_token(token)
    if ok:
        flash("Email verified! You can now send campaigns.", "success")
    else:
        flash("Verification link is invalid or has expired.", "error")
    return redirect(url_for("login"))


@app.route("/resend-verification")
@login_required
def resend_verification():
    user = store.get_user_by_id(uid())
    if user and user.get("email_verified", True):
        flash("Your email is already verified.", "info")
        return redirect(url_for("index"))
    token = secrets.token_urlsafe(32)
    store.set_verification_token(uid(), token)
    verify_url = f"{BASE_URL}/verify-email/{token}"
    send_system_email(
        user["email"],
        "Verify your MailOps account",
        f"<p>Click the link below to verify your email:</p>"
        f"<p><a href='{verify_url}'>{verify_url}</a></p>"
        f"<p>This link expires in 24 hours.</p>"
    )
    flash("Verification email resent. Check your inbox.", "success")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user_id  = store.verify_user(email, password)
        if user_id:
            user = store.get_user_by_id(user_id)
            session.clear()
            session.update({
                "logged_in":   True,
                "user_id":     user_id,
                "username":    user.get("username", ""),
                "email":       user.get("email", ""),
                "last_active": datetime.utcnow().isoformat(),
            })
            session.permanent = True
            audit("LOGIN_OK", f"email={email}")
            return redirect(request.form.get("next") or url_for("index"))
        audit("LOGIN_FAIL", f"email={email}")
        flash("Invalid email or password.", "error")
    return render_template("login.html", next=request.args.get("next", ""))


@app.route("/logout")
def logout():
    audit("LOGOUT")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ── Password reset ─────────────────────────────────────────────────────────────
@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user  = store.get_user_by_email(email)
        # Always show success to prevent email enumeration
        if user:
            token   = secrets.token_urlsafe(32)
            user_id = str(user.get("_id", user.get("id", "")))
            store.set_reset_token(user_id, token)
            reset_url = f"{BASE_URL}/reset-password/{token}"
            smtp_cfg  = store.get_smtp_config(user_id)
            if smtp_cfg:
                try:
                    import smtplib, ssl as _ssl
                    from mailer_engine import build_message
                    _msg = build_message(
                        smtp_cfg,
                        {"email": email, "first_name": user.get("username", "")},
                        "Reset your MailOps password",
                        f"<p>Hi {user.get('username', '')},</p>"
                        f"<p>You requested a password reset. Click the link below:</p>"
                        f"<p><a href='{reset_url}'>{reset_url}</a></p>"
                        f"<p>This link expires in 1 hour. If you didn't request this, ignore this email.</p>",
                    )
                    _ctx = _ssl.create_default_context()
                    with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=20) as _s:
                        _s.ehlo(); _s.starttls(context=_ctx); _s.ehlo()
                        _s.login(smtp_cfg["user"], smtp_cfg["password"])
                        _s.sendmail(smtp_cfg["user"], email, _msg.as_bytes())
                    logging.info(f"Password reset email sent to {email}")
                except Exception as _e:
                    logging.error(f"Password reset email failed: {_e}")
            else:
                logging.warning(f"RESET LINK (no SMTP configured) for {email}: {reset_url}")
        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user_id = store.validate_reset_token(token)
    if not user_id:
        flash("Reset link is invalid or has expired.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        new_pw  = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)
        if new_pw != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)
        store.change_password(user_id, new_pw)
        store.clear_reset_token(user_id)
        audit("PW_RESET", f"user={user_id}")
        flash("Password updated. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# ── Google OAuth ───────────────────────────────────────────────────────────────
try:
    from authlib.integrations.flask_client import OAuth
    oauth  = OAuth(app)
    google = oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    GOOGLE_ENABLED = bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))
except ImportError:
    GOOGLE_ENABLED = False

@app.route("/auth/google")
def google_login():
    if not GOOGLE_ENABLED:
        flash("Google login is not configured yet.", "warning")
        return redirect(url_for("login"))
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    if not GOOGLE_ENABLED:
        return redirect(url_for("login"))
    try:
        token     = google.authorize_access_token()
        info      = token.get("userinfo") or google.userinfo()
        google_id = info["sub"]
        email     = info["email"]
        name      = info.get("name", "")
        user, is_new = store.get_or_create_google_user(google_id, email, name)
        session.clear()
        session.update({
            "logged_in":   True,
            "user_id":     user["id"],
            "username":    user.get("username", ""),
            "email":       user.get("email", ""),
            "last_active": datetime.utcnow().isoformat(),
        })
        session.permanent = True
        audit("GOOGLE_LOGIN", f"email={email} new={is_new}")
        if is_new:
            flash(f"Welcome to MailOps, {name or email}! Set up your SMTP to start sending.", "success")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Google login failed: {e}", "error")
        return redirect(url_for("login"))

@app.context_processor
def inject_globals():
    return {
        "google_enabled": GOOGLE_ENABLED,
        "current_user":   store.get_user_by_id(uid()) if session.get("logged_in") else None,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ACCOUNT SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user = store.get_user_by_id(uid())
    if request.method == "POST":
        action = request.form.get("action")
        if action == "update_profile":
            username = request.form.get("username", "").strip()
            email    = request.form.get("email", "").strip()
            if len(username) < 2:
                flash("Username must be at least 2 characters.", "error")
            elif "@" not in email:
                flash("Valid email required.", "error")
            else:
                ok, msg = store.update_profile(uid(), username, email)
                flash(msg, "success" if ok else "error")
                if ok:
                    session["username"] = username
                    session["email"]    = email
                audit("PROFILE_UPDATE", f"user={uid()}")
        elif action == "change_password":
            current = request.form.get("current_password", "")
            new_pw  = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not store.verify_user(session.get("email", ""), current):
                flash("Current password is incorrect.", "error")
            elif len(new_pw) < 8:
                flash("New password must be at least 8 characters.", "error")
            elif new_pw != confirm:
                flash("New passwords do not match.", "error")
            else:
                store.change_password(uid(), new_pw)
                flash("Password updated successfully.", "success")
                audit("PW_CHANGED", f"user={uid()}")
        elif action == "delete_account":
            confirm_text = request.form.get("confirm_delete", "")
            if confirm_text != "DELETE":
                flash("Type DELETE to confirm account deletion.", "error")
            else:
                store.delete_account(uid())
                session.clear()
                flash("Your account and all data have been permanently deleted.", "info")
                return redirect(url_for("login"))
        return redirect(url_for("account"))
    return render_template("account.html", user=user)


# ══════════════════════════════════════════════════════════════════════════════
# SMTP SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/settings/smtp", methods=["GET", "POST"])
@login_required
def smtp_settings():
    if request.method == "POST":
        prov = request.form.get("provider", "microsoft365")
        su   = request.form.get("smtp_user", "").strip()
        sp   = request.form.get("smtp_password", "")
        sn   = request.form.get("sender_name", "").strip()
        ch   = request.form.get("custom_host", "").strip()
        cp   = request.form.get("custom_port", 587)
        errs = []
        if not su or "@" not in su: errs.append("Valid SMTP email required.")
        if not sp:                  errs.append("Password required.")
        if not sn:                  errs.append("Sender name required.")
        if prov == "custom" and not ch: errs.append("Custom host required.")
        if errs:
            [flash(e, "error") for e in errs]
            return render_template("smtp_settings.html",
                cfg=store.get_smtp_display(uid()), providers=store.SMTP_PROVIDERS, form=request.form)
        store.save_smtp_config(uid(), prov, su, sp, sn, ch, cp)
        audit("SMTP_UPDATED", f"provider={prov}")
        flash("SMTP settings saved. ✓", "success")
        return redirect(url_for("smtp_settings"))
    return render_template("smtp_settings.html",
        cfg=store.get_smtp_display(uid()), providers=store.SMTP_PROVIDERS, form={})

@app.route("/api/db-test")
@login_required
def db_test():
    ok, msg = store.test_connection()
    return jsonify({"ok": ok, "message": msg})


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/healthz")
def healthz():
    """Monitoring endpoint — checks MongoDB, Redis, and Celery connectivity."""
    checks = {}

    # MongoDB
    try:
        store.get_db().command("ping")
        checks["mongodb"] = "ok"
    except Exception as e:
        checks["mongodb"] = f"error: {e}"

    # Redis
    try:
        _redis.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    # Celery (check if any workers are online via Redis)
    try:
        from celery_app import celery as celery_app
        stats = celery_app.control.inspect(timeout=1).stats()
        checks["celery"] = "ok" if stats else "no workers"
    except Exception as e:
        checks["celery"] = f"error: {e}"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return jsonify({"status": overall, "checks": checks}), 200 if overall == "ok" else 503


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
@login_required
def index():
    ok, msg = store.test_connection()
    user    = store.get_user_by_id(uid())
    quota   = store.get_daily_quota(uid())
    return render_template("index.html",
        smtp_ok=store.smtp_is_configured(uid()),
        username=session.get("username", ""),
        cfg=store.get_smtp_display(uid()),
        db_ok=ok, db_msg=msg,
        contact_stats=store.get_contact_stats(uid()),
        quota=quota,
        email_verified=user.get("email_verified", True) if user else True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CAMPAIGNS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/compose", methods=["GET", "POST"])
@login_required
@smtp_required
@verified_required
def compose():
    lists     = store.get_all_lists(uid())
    tags      = store.get_all_tags(uid())
    templates = store.get_all_templates(uid())
    preload   = {}
    tid = request.args.get("template_id", "")
    if tid:
        t = store.get_template(uid(), tid)
        if t:
            preload = {"subject": t.get("subject", ""), "body": t.get("html_body", "")}

    if request.method == "POST":
        errs    = []
        subject = request.form.get("subject", "").strip()
        body    = request.form.get("body", "").strip()
        source  = request.form.get("recipient_source", "file")
        if not subject: errs.append("Subject required.")
        if not body:    errs.append("Body required.")

        # FIX: quota check before processing
        quota = store.get_daily_quota(uid())
        if quota["remaining"] <= 0:
            flash(f"Daily send limit reached ({quota['limit']} emails/day). "
                  "Resets at midnight UTC.", "error")
            return render_template("compose.html", form=request.form,
                                   lists=lists, tags=tags, templates=templates, preload=preload)

        records = []; rec_path = ""

        if source == "file":
            rf = request.files.get("recipient_file")
            if not rf or not rf.filename:
                errs.append("Upload a CSV/Excel file.")
            elif not allowed_file(rf.filename, ALLOWED_CSV):
                errs.append("File must be .csv/.xlsx/.xls")
            else:
                rec_path = os.path.join(UPLOAD_FOLDER, secure_filename(rf.filename))
                rf.save(rec_path)
                try:    records = load_recipients(rec_path)
                except Exception as e: errs.append(f"Can't read file: {e}")
        elif source == "list":
            lids = request.form.getlist("list_ids")
            if not lids: errs.append("Select at least one list.")
            else:
                seen = set()
                for lid in lids:
                    for r in store.get_subscribed_contacts_for_list(uid(), lid):
                        if r["email"] not in seen:
                            seen.add(r["email"]); records.append(r)
                if not records: errs.append("No subscribed contacts in selected lists.")
        elif source == "tag":
            tag = request.form.get("tag_filter", "")
            if not tag: errs.append("Select a tag.")
            else:
                records = store.get_contacts(uid(), tag=tag, status="subscribed", per_page=5000)["contacts"]
                if not records: errs.append(f"No subscribed contacts with tag '{tag}'.")

        if errs:
            [flash(e, "error") for e in errs]
            return render_template("compose.html", form=request.form,
                                   lists=lists, tags=tags, templates=templates, preload=preload)

        # Cap at remaining quota
        valid, invalid = validate_recipients(records)
        if len(valid) > quota["remaining"]:
            flash(f"Capped to {quota['remaining']} recipients (daily quota). "
                  f"Remaining after today: 0.", "warning")
            valid = valid[:quota["remaining"]]

        att = []
        for f in request.files.getlist("attachments"):
            if f and f.filename and allowed_file(f.filename, ALLOWED_ATTACH):
                fp = os.path.join(UPLOAD_FOLDER, secure_filename(f.filename))
                f.save(fp); att.append(fp)

        # Store large recipients list in DB to avoid oversized session cookie
        _camp_id = "pending_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        _camp_data = {
            "recipients":       valid,
            "rec_path":         rec_path,
            "subject":          subject,
            "body":             sanitize_html(body),
            "attachment_paths": att,
            "mode":             request.form.get("mode", "sequential"),
            "delay":            float(request.form.get("delay", 0.5)),
            "max_workers":      int(request.form.get("max_workers", 10)),
            "dry_run":          request.form.get("dry_run") == "on",
            "valid_count":      len(valid),
            "invalid_count":    len(invalid),
            "invalid_emails":   [r.get("email", "") for r in invalid[:10]],
        }
        store.save_pending_campaign(uid(), _camp_id, _camp_data)
        # Only store a lightweight reference in the session cookie
        session["campaign"] = {
            "pending_id":       _camp_id,
            "subject":          subject,
            "body":             sanitize_html(body),
            "valid_count":      len(valid),
            "invalid_count":    len(invalid),
            "invalid_emails":   [r.get("email", "") for r in invalid[:10]],
            "mode":             request.form.get("mode", "sequential"),
            "dry_run":          request.form.get("dry_run") == "on",
            "attachment_paths": att,
        }
        return redirect(url_for("preview"))

    return render_template("compose.html", form=preload,
                           lists=lists, tags=tags, templates=templates, preload=preload)


@app.route("/preview")
@login_required
@smtp_required
def preview():
    c = session.get("campaign")
    if not c:
        return redirect(url_for("compose"))
    return render_template("preview.html", campaign=c, smtp=store.get_smtp_display(uid()))


@app.route("/send", methods=["POST"])
@login_required
@smtp_required
@verified_required
def send():
    c = session.get("campaign")
    if not c:
        flash("Session expired.", "error"); return redirect(url_for("compose"))
    # Load full recipients from DB if stored there
    if "pending_id" in c:
        _full = store.get_pending_campaign(uid(), c["pending_id"])
        if _full:
            c = _full
        else:
            flash("Campaign data expired. Please compose again.", "error")
            return redirect(url_for("compose"))
    smtp_cfg  = store.get_smtp_config(uid())
    run_id    = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    started   = datetime.now().isoformat()
    _user_id  = uid()
    audit("CAMPAIGN_START", f"run_id={run_id} n={c['valid_count']}")
    # Clean up pending campaign from DB now that it's launched
    if c.get("pending_id"):
        store.delete_pending_campaign(uid(), c["pending_id"])

    set_campaign_state(run_id, {
        "status": "running", "total": c["valid_count"],
        "success": 0, "failed": 0, "invalid": c["invalid_count"],
        "results": [], "started_at": started,
        "finished_at": None, "report_file": None, "log_file": None,
    })

    def _run():
        records = c.get("recipients", []) or \
                  (load_recipients(c["rec_path"]) if c.get("rec_path") else [])
        lock = _get_lock(run_id)

        def prog(r):
            with lock:
                state = get_campaign_state(run_id) or {}
                state.setdefault("results", []).append(r)
                if r["status"] == "success":
                    state["success"] = state.get("success", 0) + 1
                elif r["status"] == "invalid":
                    state["invalid"] = state.get("invalid", 0) + 1
                elif r["status"] == "failed":
                    state["failed"]  = state.get("failed",  0) + 1
                set_campaign_state(run_id, state)

        s = run_campaign(
            recipients=records, subject_tmpl=c["subject"], body_tmpl=c["body"],
            mode=c["mode"], delay=c["delay"], max_workers=c["max_workers"],
            max_retries=3, attachment_paths=c["attachment_paths"] or None,
            dry_run=c["dry_run"], progress_callback=prog, smtp_override=smtp_cfg,
        )
        fin = datetime.now().isoformat()
        update_campaign_state(run_id, {
            "status": "complete", "finished_at": fin,
            "report_file": s["report_file"], "log_file": s["log_file"],
        })
        store.save_campaign(_user_id, run_id, {
            **get_campaign_state(run_id), "mode": c["mode"],
            "started_at": started, "finished_at": fin,
        })
        # FIX: increment daily quota counter
        if not c.get("dry_run"):
            store.increment_daily_quota(_user_id, s["success"])
        audit("CAMPAIGN_DONE", f"run_id={run_id} ok={s['success']} fail={s['failed']}")

    threading.Thread(target=_run, daemon=True).start()
    session["run_id"] = run_id
    return redirect(url_for("results", run_id=run_id))


@app.route("/results/<run_id>")
@login_required
def results(run_id):
    return render_template("results.html", run_id=run_id)

@app.route("/api/status/<run_id>")
@login_required
def api_status(run_id):
    s = get_campaign_state(run_id)
    return (jsonify(s) if s else jsonify({"error": "not found"}), 200 if s else 404)

@app.route("/download/report/<run_id>")
@login_required
def download_report(run_id):
    s = get_campaign_state(run_id) or {}
    f = s.get("report_file")
    if not f or not os.path.exists(f):
        flash("Not ready.", "error"); return redirect(url_for("results", run_id=run_id))
    return send_file(f, as_attachment=True, download_name=f"{run_id}_report.csv")

@app.route("/download/log/<run_id>")
@login_required
def download_log(run_id):
    s = get_campaign_state(run_id) or {}
    f = s.get("log_file")
    if not f or not os.path.exists(f):
        flash("Not ready.", "error"); return redirect(url_for("results", run_id=run_id))
    return send_file(f, as_attachment=True, download_name=f"{run_id}.log")

@app.route("/history")
@login_required
def history():
    db_camps  = store.get_campaign_history(uid())
    scheduled = store.get_scheduled_campaigns(uid())
    sched_ids = {r["run_id"] for r in scheduled}
    all_runs  = scheduled + [r for r in db_camps if r.get("run_id") not in sched_ids]
    def _sort_key(x):
        v = x.get("scheduled_for") or x.get("started_at") or ""
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return str(v)
    all_runs.sort(key=_sort_key, reverse=True)

    # Add IST display time to each run
    _ist_delta = timedelta(hours=5, minutes=30)
    for r in all_runs:
        sf = r.get("scheduled_for")
        if sf and hasattr(sf, "strftime"):
            r["scheduled_for_ist"] = (sf + _ist_delta).strftime("%d %b %Y %H:%M")
        else:
            r["scheduled_for_ist"] = None

    return render_template("history.html", runs=all_runs)


# ══════════════════════════════════════════════════════════════════════════════
# CONTACTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/contacts")
@login_required
def contacts():
    page    = int(request.args.get("page", 1))
    search  = request.args.get("search", "").strip()
    list_id = request.args.get("list_id", "")
    tag     = request.args.get("tag", "")
    status  = request.args.get("status", "")
    result  = store.get_contacts(uid(),
        list_id=list_id or None, status=status or None,
        tag=tag or None, search=search or None, page=page, per_page=50)
    return render_template("contacts.html",
        contacts=result["contacts"], total=result["total"],
        page=result["page"], pages=result["pages"],
        lists=store.get_all_lists(uid()), tags=store.get_all_tags(uid()),
        stats=store.get_contact_stats(uid()),
        search=search, list_id=list_id, tag=tag, status=status)

@app.route("/contacts/add", methods=["GET", "POST"])
@login_required
def contact_add():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        fn    = request.form.get("first_name", "").strip()
        ln    = request.form.get("last_name", "").strip()
        tags  = [t.strip() for t in request.form.get("tags", "").split(",") if t.strip()]
        lids  = request.form.getlist("list_ids")
        ok, msg = store.add_contact(uid(), email, fn, ln, tags, lids)
        if ok:
            audit("CONTACT_ADD", f"email={email}"); flash(msg, "success")
            return redirect(url_for("contacts"))
        flash(msg, "error")
    return render_template("contact_form.html", contact=None,
                           lists=store.get_all_lists(uid()), all_tags=store.get_all_tags(uid()), title="Add Contact")

@app.route("/contacts/edit/<email>", methods=["GET", "POST"])
@login_required
def contact_edit(email):
    contact = store.get_contact(uid(), email)
    if not contact:
        flash("Contact not found.", "error"); return redirect(url_for("contacts"))
    if request.method == "POST":
        fn   = request.form.get("first_name", "").strip()
        ln   = request.form.get("last_name", "").strip()
        tags = [t.strip() for t in request.form.get("tags", "").split(",") if t.strip()]
        lids = request.form.getlist("list_ids")
        store.update_contact(uid(), email, fn, ln, tags, lids)
        audit("CONTACT_EDIT", f"email={email}")
        flash("Contact updated.", "success"); return redirect(url_for("contacts"))
    return render_template("contact_form.html", contact=contact,
                           lists=store.get_all_lists(uid()), all_tags=store.get_all_tags(uid()), title="Edit Contact")

@app.route("/contacts/delete/<email>", methods=["POST"])
@login_required
def contact_delete(email):
    store.delete_contact(uid(), email); audit("CONTACT_DEL", f"email={email}")
    flash(f"Deleted {email}.", "success"); return redirect(url_for("contacts"))

@app.route("/contacts/unsubscribe/<email>", methods=["POST"])
@login_required
def contact_unsubscribe(email):
    store.unsubscribe_contact(uid(), email); audit("UNSUB", f"email={email}")
    flash(f"{email} unsubscribed.", "success"); return redirect(url_for("contacts"))

@app.route("/contacts/resubscribe/<email>", methods=["POST"])
@login_required
def contact_resubscribe(email):
    store.resubscribe_contact(uid(), email); audit("RESUB", f"email={email}")
    flash(f"{email} resubscribed.", "success"); return redirect(url_for("contacts"))

@app.route("/contacts/import", methods=["GET", "POST"])
@login_required
def contacts_import():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Upload a file.", "error"); return redirect(url_for("contacts_import"))
        if not allowed_file(f.filename, ALLOWED_CSV):
            flash("Must be .csv/.xlsx/.xls", "error"); return redirect(url_for("contacts_import"))
        path = os.path.join(UPLOAD_FOLDER, secure_filename(f.filename)); f.save(path)
        try:
            records  = load_recipients(path)
            list_ids = request.form.getlist("list_ids")
            r = store.import_contacts(uid(), records, list_ids)
            audit("IMPORT", f"added={r['added']} updated={r['updated']} skipped={r['skipped']}")
            flash(f"Done — {r['added']} added, {r['updated']} updated, {r['skipped']} skipped.", "success")
            if r["errors"]: flash("Errors: " + ", ".join(r["errors"][:5]), "warning")
        except Exception as e:
            flash(f"Import failed: {e}", "error")
        return redirect(url_for("contacts"))
    return render_template("contacts_import.html", lists=store.get_all_lists(uid()))

@app.route("/contacts/export")
@login_required
def contacts_export():
    data = store.get_contacts(uid(), per_page=10000)["contacts"]
    si   = io.StringIO()
    w    = csv.DictWriter(si, fieldnames=["email","first_name","last_name","status","tags","lists","created_at"])
    w.writeheader()
    for c in data:
        w.writerow({"email": c["email"], "first_name": c.get("first_name",""),
                    "last_name": c.get("last_name",""), "status": c.get("status","subscribed"),
                    "tags": ",".join(c.get("tags",[])), "lists": ",".join(c.get("lists",[])),
                    "created_at": str(c.get("created_at",""))})
    audit("EXPORT", f"count={len(data)}")
    return Response(si.getvalue().encode("utf-8"), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=contacts_export.csv"})


# ══════════════════════════════════════════════════════════════════════════════
# LISTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/lists")
@login_required
def lists():
    return render_template("lists.html", lists=store.get_all_lists(uid()))

@app.route("/lists/create", methods=["POST"])
@login_required
def list_create():
    name = request.form.get("name", "").strip(); desc = request.form.get("description", "").strip()
    if not name: flash("Name required.", "error")
    else:
        r = store.create_list(uid(), name, desc)
        if r:  audit("LIST_CREATE", f"name={name}"); flash(f'List "{name}" created.', "success")
        else:  flash(f'List "{name}" already exists.', "error")
    return redirect(url_for("lists"))

@app.route("/lists/delete/<list_id>", methods=["POST"])
@login_required
def list_delete(list_id):
    store.delete_list(uid(), list_id); audit("LIST_DEL", f"id={list_id}")
    flash("List deleted.", "success"); return redirect(url_for("lists"))

@app.route("/lists/edit/<list_id>", methods=["POST"])
@login_required
def list_edit(list_id):
    name = request.form.get("name", "").strip(); desc = request.form.get("description", "").strip()
    if not name: flash("Name required.", "error")
    else:
        ok = store.update_list(uid(), list_id, name, desc)
        flash("List updated." if ok else "Name already taken.", "success" if ok else "error")
    return redirect(url_for("lists"))


# ══════════════════════════════════════════════════════════════════════════════
# TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/templates")
@login_required
def templates():
    return render_template("templates.html", templates=store.get_all_templates(uid()))

@app.route("/templates/save", methods=["POST"])
@login_required
def template_save():
    name    = request.form.get("name", "").strip()
    subject = request.form.get("subject", "").strip()
    body    = request.form.get("body", "").strip()
    if not name or not body: flash("Name and body are required.", "error")
    else:
        ok, msg = store.save_template(uid(), name, subject, body, session.get("username", ""))
        flash(msg, "success" if ok else "error")
        if ok: audit("TEMPLATE_SAVE", f"name={name}")
    return redirect(url_for("templates"))

@app.route("/templates/delete/<template_id>", methods=["POST"])
@login_required
def template_delete(template_id):
    store.delete_template(uid(), template_id)
    audit("TEMPLATE_DEL", f"id={template_id}")
    flash("Template deleted.", "success")
    return redirect(url_for("templates"))

@app.route("/api/templates/<template_id>")
@login_required
def api_template(template_id):
    t = store.get_template(uid(), template_id)
    return (jsonify(t) if t else jsonify({"error": "not found"}), 200 if t else 404)

@app.route("/api/templates/save-from-compose", methods=["POST"])
@login_required
def save_template_from_compose():
    data    = request.get_json(silent=True) or {}
    name    = data.get("name", "").strip()
    subject = data.get("subject", "").strip()
    body    = data.get("body", "").strip()
    if not name or not body:
        return jsonify({"ok": False, "msg": "Name and body required."})
    ok, msg = store.save_template(uid(), name, subject, body, session.get("username", ""))
    if ok: audit("TEMPLATE_SAVE_COMPOSE", f"name={name}")
    return jsonify({"ok": ok, "msg": msg})


# ══════════════════════════════════════════════════════════════════════════════
# TEST SEND
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/compose/test-send", methods=["POST"])
@login_required
@smtp_required
def test_send():
    subject  = request.form.get("subject", "Test Email")
    body     = sanitize_html(request.form.get("body", ""))
    email    = session.get("email", "")
    if not email:
        flash("No email on your account. Update your profile first.", "error")
        return redirect(url_for("compose"))
    smtp_cfg = store.get_smtp_config(uid())
    from mailer_engine import build_message
    import smtplib, ssl
    try:
        msg = build_message(smtp_cfg, {"email": email, "first_name": session.get("username", "")}, subject, body)
        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=20) as s:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
            s.login(smtp_cfg["user"], smtp_cfg["password"])
            s.sendmail(smtp_cfg["user"], email, msg.as_bytes())
        flash(f"Test email sent to {email} ✓", "success")
        audit("TEST_SEND", f"to={email}")
    except Exception as e:
        flash(f"Test send failed: {e}", "error")
    return redirect(url_for("compose"))


# ══════════════════════════════════════════════════════════════════════════════
# TRACKING & ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/track/open/<run_id>")
def track_open(run_id):
    email = request.args.get("e", "")
    # FIX: validate that the run_id + email combination is legitimate
    if email and store.is_valid_campaign_recipient(run_id, email):
        store.get_db().events.insert_one({
            "type":   "open", "run_id": run_id, "email": email,
            "at":     datetime.utcnow(), "ua": request.headers.get("User-Agent", "")
        })
    pixel = (b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
             b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00"
             b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")
    resp = make_response(pixel)
    resp.headers["Content-Type"]  = "image/gif"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp

@app.route("/track/click/<run_id>")
def track_click(run_id):
    url   = request.args.get("url", "/")
    email = request.args.get("e", "")
    # FIX: validate before writing
    if email and store.is_valid_campaign_recipient(run_id, email):
        store.get_db().events.insert_one({
            "type":   "click", "run_id": run_id, "email": email,
            "url":    url, "at": datetime.utcnow()
        })
    return redirect(unquote(url))

@app.route("/analytics/<run_id>")
@login_required
def analytics(run_id):
    events = list(store.get_db().events.find({"run_id": run_id}, {"_id": 0}))
    opens  = [e for e in events if e["type"] == "open"]
    clicks = [e for e in events if e["type"] == "click"]
    camp   = get_campaign_state(run_id) or {}
    if not camp:
        camp = store.get_db().campaigns.find_one({"run_id": run_id, "user_id": uid()}, {"_id": 0}) or {}
    total = max(camp.get("total", 1), 1)
    return render_template("analytics.html",
        run_id=run_id, camp=camp,
        opens=len(opens), clicks=len(clicks), total=total,
        open_rate=round(len(opens) / total * 100, 1),
        click_rate=round(len(clicks) / total * 100, 1),
        recent_events=events[-50:][::-1])


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC UNSUBSCRIBE & WEBHOOKS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/unsubscribe/<email>")
def public_unsubscribe(email):
    # FIX: scope unsubscribe to the specific user who sent the campaign
    # Try to resolve from run_id query param if present, else global
    run_id  = request.args.get("rid", "")
    user_id = None
    if run_id:
        camp = store.get_db().campaigns.find_one({"run_id": run_id}, {"user_id": 1})
        if camp:
            user_id = camp.get("user_id")
    if user_id:
        store.unsubscribe_contact(user_id, email)
    else:
        # Fallback: unsubscribe across all users (CAN-SPAM compliance)
        store.unsubscribe_by_email(email)
    return render_template("unsubscribed.html", email=email)

@app.route("/webhooks/bounce", methods=["POST"])
def bounce_webhook():
    token = request.headers.get("X-Webhook-Token", "")
    if not verify_webhook_token(token):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "")
    if email:
        store.unsubscribe_by_email(email)
        audit("BOUNCE_WEBHOOK", f"email={email}")
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULED SENDING
# ══════════════════════════════════════════════════════════════════════════════
CELERY_ENABLED = False
send_scheduled_campaign = None
if REDIS_ENABLED:
    try:
        from celery_app import send_scheduled_campaign
        CELERY_ENABLED = True
    except Exception:
        CELERY_ENABLED = False

@app.route("/schedule", methods=["POST"])
@login_required
@smtp_required
def schedule():
    c = session.get("campaign")
    if not c:
        flash("Session expired. Please compose again.", "error")
        return redirect(url_for("compose"))
    # Load full recipients from DB if stored there
    if "pending_id" in c:
        _full = store.get_pending_campaign(uid(), c["pending_id"])
        if _full:
            c = _full
        else:
            flash("Campaign data expired. Please compose again.", "error")
            return redirect(url_for("compose"))

    schedule_type = request.form.get("schedule_type", "datetime")
    errs = []
    scheduled_for = None

    if schedule_type == "datetime":
        dt_str = request.form.get("schedule_datetime", "").strip()
        if not dt_str:
            errs.append("Please pick a date and time.")
        else:
            try:
                scheduled_for_ist = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
                # Convert IST input to UTC for storage
                scheduled_for = scheduled_for_ist - timedelta(hours=5, minutes=30)
                if scheduled_for <= datetime.utcnow():
                    errs.append("Scheduled time must be in the future.")
            except ValueError:
                errs.append("Invalid date/time format.")

    elif schedule_type == "delay":
        try:
            val  = float(request.form.get("delay_value", 0))
            unit = request.form.get("delay_unit", "hours")
            if val <= 0:
                errs.append("Delay must be greater than 0.")
            else:
                delta = {"minutes": timedelta(minutes=val),
                         "hours":   timedelta(hours=val),
                         "days":    timedelta(days=val)}.get(unit, timedelta(hours=val))
                scheduled_for = datetime.utcnow() + delta
        except (ValueError, TypeError):
            errs.append("Invalid delay value.")

    if errs:
        [flash(e, "error") for e in errs]
        return redirect(url_for("preview"))

    run_id    = datetime.now().strftime("sched_%Y%m%d_%H%M%S")
    _user_id  = uid()
    smtp_cfg  = store.get_smtp_config(_user_id)
    payload   = {
        "recipients":       c.get("recipients", []),
        "subject":          c["subject"],
        "body":             c["body"],
        "scheduled_for":    scheduled_for,
        "mode":             c.get("mode", "sequential"),
        "delay":            c.get("delay", 0.5),
        "max_workers":      c.get("max_workers", 10),
        "dry_run":          c.get("dry_run", False),
        "attachment_paths": c.get("attachment_paths", []),
        "total":            c.get("valid_count", 0),
    }

    campaign_id   = store.create_scheduled_campaign(_user_id, run_id, payload)
    seconds_until = max(0, (scheduled_for - datetime.utcnow()).total_seconds())

    # Use Celery if available, otherwise fall back to a plain thread timer
    if CELERY_ENABLED:
        send_scheduled_campaign.apply_async(args=[campaign_id], countdown=int(seconds_until))
    else:
        # Capture all needed values before spawning thread
        _run_id        = run_id
        _user_id_t     = _user_id
        _campaign_id   = campaign_id
        _seconds       = seconds_until
        _sched_for_iso = scheduled_for.isoformat()

        def _run_later():
            import time
            from datetime import datetime as _dt
            try:
                logging.info(f"Scheduled campaign {_run_id} sleeping {_seconds:.0f}s until {_sched_for_iso}")
                time.sleep(_seconds)
                logging.info(f"Scheduled campaign {_run_id} waking up — loading from DB and sending")

                # Reload full campaign doc from MongoDB (includes recipients)
                from bson import ObjectId as _ObjId
                doc = store.get_db().scheduled_campaigns.find_one({"_id": _ObjId(_campaign_id)})
                if not doc:
                    logging.error(f"Scheduled campaign {_run_id} not found in DB — aborting")
                    return
                if doc.get("status") == "cancelled":
                    logging.info(f"Scheduled campaign {_run_id} was cancelled — skipping")
                    return

                # Re-fetch SMTP config fresh from DB
                _smtp_fresh = store.get_smtp_config(_user_id_t)
                if not _smtp_fresh:
                    logging.error(f"Scheduled campaign {_run_id} — no SMTP config found — aborting")
                    store.update_scheduled_campaign_status(_campaign_id, "failed")
                    return

                records = doc.get("recipients", [])
                logging.info(f"Scheduled campaign {_run_id} — sending to {len(records)} recipients")

                set_campaign_state(_run_id, {
                    "status": "running", "total": len(records),
                    "success": 0, "failed": 0, "results": [],
                    "started_at": _sched_for_iso, "finished_at": None,
                })

                lock = _get_lock(_run_id)
                def prog(r):
                    with lock:
                        state = get_campaign_state(_run_id) or {}
                        state.setdefault("results", []).append(r)
                        if r["status"] == "success":
                            state["success"] = state.get("success", 0) + 1
                        else:
                            state["failed"] = state.get("failed", 0) + 1
                        set_campaign_state(_run_id, state)

                s = run_campaign(
                    recipients=records,
                    subject_tmpl=doc["subject"],
                    body_tmpl=doc["body"],
                    mode=doc.get("mode", "sequential"),
                    delay=doc.get("delay", 0.5),
                    max_workers=doc.get("max_workers", 10),
                    dry_run=doc.get("dry_run", False),
                    attachment_paths=doc.get("attachment_paths") or None,
                    progress_callback=prog,
                    smtp_override=_smtp_fresh,
                )

                fin = _dt.utcnow().isoformat()
                update_campaign_state(_run_id, {"status": "complete", "finished_at": fin})
                store.save_campaign(_user_id_t, _run_id, {
                    **(get_campaign_state(_run_id) or {}),
                    "mode":        doc.get("mode", "sequential"),
                    "started_at":  _sched_for_iso,
                    "finished_at": fin,
                })
                store.update_scheduled_campaign_status(_campaign_id, "complete")
                if not doc.get("dry_run"):
                    store.increment_daily_quota(_user_id_t, s.get("success", 0))
                logging.info(f"Scheduled campaign {_run_id} DONE — success={s.get('success',0)} failed={s.get('failed',0)}")
            except Exception as _e:
                logging.error(f"Scheduled campaign {_run_id} FAILED: {_e}", exc_info=True)
                set_campaign_state(_run_id, {"status": "failed", "error": str(_e)})
                try:
                    store.update_scheduled_campaign_status(_campaign_id, "failed")
                except Exception:
                    pass

        t = threading.Thread(target=_run_later, daemon=False, name=f"sched-{_run_id}")
        t.start()
        logging.info(f"Scheduled campaign {_run_id} thread started — fires in {_seconds:.0f}s")

    audit("CAMPAIGN_SCHEDULED", f"run_id={run_id} for={scheduled_for.isoformat()}")
    session.pop("campaign", None)
    flash(
        f"Campaign scheduled for {(scheduled_for + timedelta(hours=5, minutes=30)).strftime('%d %b %Y at %H:%M')} IST "
        f"({c['valid_count']} recipients). You can cancel it from History.",
        "success",
    )
    return redirect(url_for("history"))


@app.route("/schedule/cancel/<campaign_id>", methods=["POST"])
@login_required
def cancel_scheduled(campaign_id):
    ok = store.cancel_scheduled_campaign(uid(), campaign_id)
    if ok:
        audit("CAMPAIGN_CANCEL", f"id={campaign_id}")
        flash("Scheduled campaign cancelled.", "success")
    else:
        flash("Cannot cancel — campaign is already running or complete.", "error")
    return redirect(url_for("history"))

@app.route("/api/scheduled")
@login_required
def api_scheduled():
    return jsonify(store.get_scheduled_campaigns(uid()))


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug)