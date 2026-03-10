# MailOps — Bulk Email Campaign Platform

A self-hosted, zero-cost bulk email platform with multi-tenancy, Google OAuth, scheduled sending, and campaign analytics.

---

## Quick Start

```bash
cd mailer
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env — at minimum set FLASK_SECRET_KEY, MONGO_URI, and BASE_URL

python app.py
```

Open **http://localhost:5000** — click **Create an account** to register.

---

## First Run Flow

1. **Register** at `/register` — open registration, no invite required
2. **Verify your email** — check your inbox and click the verification link
3. **Configure SMTP** at `/settings/smtp` — pick your provider and enter credentials
4. **Send campaigns** — compose, preview, and send or schedule

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Required | Description |
|---|---|---|
| `FLASK_SECRET_KEY` | ✅ | Random hex string — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `HTTPS` | production | Set `true` when behind HTTPS to enable secure cookies and redirect |
| `FLASK_DEBUG` | dev only | `true` for development. **Never in production.** |
| `MONGO_URI` | ✅ | MongoDB connection string |
| `MONGO_DB` | ✅ | Database name (default: `mailops`) |
| `REDIS_URL` | ✅ | Redis connection string — required for Celery and rate limiting |
| `BASE_URL` | ✅ | Public URL of your app, no trailing slash (e.g. `https://mail.yourdomain.com`) |
| `GOOGLE_CLIENT_ID` | optional | Enables Google OAuth sign-in |
| `GOOGLE_CLIENT_SECRET` | optional | Required with `GOOGLE_CLIENT_ID` |
| `SENDGRID_API_KEY` | recommended | For sending verification + password reset emails |
| `SYSTEM_EMAIL_FROM` | recommended | From address for system emails |
| `DEFAULT_DAILY_LIMIT` | optional | Daily send limit per user (default: 500) |

---

## Running the Full Stack

MailOps requires Flask, Celery, and Redis to be running simultaneously for scheduled sending.

**Terminal 1 — Web server:**
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

**Terminal 2 — Celery worker:**
```bash
celery -A celery_app worker --loglevel=info --pool=solo
```

**Terminal 3 — Celery beat scheduler (for scheduled campaigns):**
```bash
celery -A celery_app beat --loglevel=info
```

**Terminal 4 — Flower monitor (optional):**
```bash
celery -A celery_app flower --port=5555
```

---

## Security

| What | How |
|---|---|
| User passwords | PBKDF2-SHA256 (werkzeug) — never stored plain |
| SMTP passwords | Fernet AES-128-CBC + HMAC-SHA256 encrypted at rest |
| Encryption key | Derived from `FLASK_SECRET_KEY` via PBKDF2 — never written to disk |
| Session cookies | `HttpOnly`, `SameSite=Lax`, `Secure` when `HTTPS=true` |
| CSRF | Flask-WTF on all state-changing routes |
| Rate limiting | Redis-backed flask-limiter (login: 5/min, register: 10/min) |
| Security headers | X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, CSP, Referrer-Policy |

---

## SMTP Providers Supported

- Microsoft 365 / Outlook (`smtp.office365.com:587`)
- Gmail / Google Workspace (`smtp.gmail.com:587`)
- Zoho Mail, Yahoo Mail, SendGrid, Mailgun
- Custom SMTP (any host/port)

---

## Project Structure

```
mailer/
├── app.py              # Flask routes, auth, middleware
├── mailer_engine.py    # SMTP sending engine, tracking URL injection
├── store.py            # MongoDB data layer (multi-tenant, encrypted SMTP)
├── celery_app.py       # Celery tasks + beat scheduler
├── requirements.txt    # Pinned dependencies
├── .env.example        # Template for environment configuration
├── .gitignore          # Excludes .env, uploads/, logs/
├── templates/          # Jinja2 HTML templates (18 total)
├── uploads/            # Temporary file uploads (gitignored)
└── logs/               # Audit + campaign logs (gitignored)
```

---

## Monitoring

- **Health check:** `GET /healthz` — returns JSON status of MongoDB, Redis, and Celery
- **Audit log:** `logs/audit.log` — all auth events, campaign starts, data changes
- **Campaign logs:** `logs/run_YYYYMMDD_HHMMSS.log` — per-campaign SMTP activity
