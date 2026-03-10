"""
mailer_engine.py
Core sending engine — SMTP, template rendering, attachments, retry, CSV report.
"""

import smtplib, ssl, os, re, csv, logging, threading, time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from concurrent.futures import ThreadPoolExecutor, as_completed
from jinja2 import Environment, BaseLoader
from dotenv import load_dotenv

load_dotenv()

# ── Logger ─────────────────────────────────────────────────────────────────────
def get_run_logger(run_id):
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger(run_id)
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(f"logs/{run_id}.log")
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(fh)
    return logger

# ── Validation ─────────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+$")

def is_valid_email(addr):
    return bool(EMAIL_RE.match(str(addr).strip()))

def validate_recipients(records):
    valid, invalid, seen = [], [], set()
    for r in records:
        email = str(r.get("email", "")).strip().lower()
        if not is_valid_email(email):
            invalid.append({**r, "error": "Invalid email format"})
        elif email in seen:
            invalid.append({**r, "error": "Duplicate"})
        else:
            seen.add(email)
            r["email"] = email
            valid.append(r)
    return valid, invalid

# ── Template ───────────────────────────────────────────────────────────────────
def render_template(tmpl_str, context):
    rendered = Environment(loader=BaseLoader()).from_string(tmpl_str).render(**context)
    # If the body has no HTML block tags, convert newlines to <br> so formatting is preserved
    import re as _re
    has_block_tags = bool(_re.search(r'<(p|div|br|h[1-6]|table|ul|ol|li|blockquote)[^>]*>', rendered, _re.IGNORECASE))
    if not has_block_tags:
        rendered = rendered.replace("\r\n", "\n").replace("\r", "\n")
        rendered = "<br>".join(rendered.split("\n"))
    return rendered

# ── SMTP config ────────────────────────────────────────────────────────────────
def get_smtp_config(override=None):
    if override:
        return override
    return {
        "host": os.getenv("SMTP_HOST", "smtp.office365.com"),
        "port": int(os.getenv("SMTP_PORT", 587)),
        "user": os.getenv("SMTP_USER", ""),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "sender_name": os.getenv("SENDER_NAME", ""),
    }

# ── MIME type detection ────────────────────────────────────────────────────────
def _mime_type_for(path):
    """Return (maintype, subtype) based on file extension."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    mapping = {
        "jpg":  ("image", "jpeg"),
        "jpeg": ("image", "jpeg"),
        "png":  ("image", "png"),
        "gif":  ("image", "gif"),
        "webp": ("image", "webp"),
        "bmp":  ("image", "bmp"),
        "pdf":  ("application", "pdf"),
        "docx": ("application", "vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xlsx": ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "txt":  ("text", "plain"),
        "csv":  ("text", "csv"),
        "zip":  ("application", "zip"),
    }
    return mapping.get(ext, ("application", "octet-stream"))

# ── Build message ──────────────────────────────────────────────────────────────
def build_message(smtp_cfg, recipient, subject_tmpl, body_tmpl, attachment_paths=None, run_id=None):
    """
    Build MIME email. Structure:

    WITH attachments:          WITHOUT attachments:
      multipart/mixed            multipart/alternative
        multipart/alternative      text/plain
          text/plain               text/html
          text/html
        <attachment>...
    """
    context         = {k: str(v) for k, v in recipient.items()}
    subject         = render_template(subject_tmpl, context)
    body_html       = render_template(body_tmpl, context)
    recipient_email = context["email"]

    # ── Tracking (only injected when run_id is provided) ──────────────────────
    if run_id:
        base_url = os.getenv("BASE_URL", "http://localhost:5000").rstrip("/")
        # Open tracking pixel
        body_html += (
            f'<img src="{base_url}/track/open/{run_id}?e={recipient_email}"'
            ' width="1" height="1" style="display:none">'
        )
        # Click tracking — wrap all http/https links
        def wrap_link(m):
            original_url = m.group(1)
            return f'href="{base_url}/track/click/{run_id}?url={original_url}&e={recipient_email}"'
        body_html = re.sub(r'href="(https?://[^"]+)"', wrap_link, body_html)

    # Wrap body in an email-safe container to preserve fonts, alignment, spacing
    if not body_html.strip().startswith("<!DOCTYPE") and "<html" not in body_html:
        body_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{{margin:0;padding:0;background:#ffffff;font-family:Arial,sans-serif;font-size:14px;color:#222222;}}
  .wrapper{{max-width:640px;margin:0 auto;padding:24px 20px;}}
  p{{margin:0 0 1em 0;}} a{{color:#1a73e8;}}
  img{{max-width:100%;height:auto;}}
</style></head>
<body><div class="wrapper">{body_html}</div></body></html>"""

    plain     = re.sub(r"<[^>]+>", "", body_html)
    valid_att = [p for p in (attachment_paths or []) if p and os.path.exists(p)]

    if valid_att:
        outer = MIMEMultipart("mixed")
        alt   = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain,     "plain", "utf-8"))
        alt.attach(MIMEText(body_html, "html",  "utf-8"))
        outer.attach(alt)
    else:
        outer = MIMEMultipart("alternative")
        outer.attach(MIMEText(plain,     "plain", "utf-8"))
        outer.attach(MIMEText(body_html, "html",  "utf-8"))

    sender = f"{smtp_cfg['sender_name']} <{smtp_cfg['user']}>" if smtp_cfg.get("sender_name") else smtp_cfg["user"]
    outer["From"]    = sender
    outer["To"]      = recipient["email"]
    outer["Subject"] = subject

    for path in valid_att:
        maintype, subtype = _mime_type_for(path)
        filename = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()

        if maintype == "text":
            part = MIMEText(data.decode("utf-8", errors="replace"), subtype, "utf-8")
        else:
            part = MIMEBase(maintype, subtype)
            part.set_payload(data)
            encoders.encode_base64(part)

        part.add_header("Content-Disposition", "attachment", filename=filename)
        outer.attach(part)

    return outer

# ── Send one ───────────────────────────────────────────────────────────────────
def send_one(smtp_cfg, recipient, subject_tmpl, body_tmpl, attachment_paths,
             max_retries, logger, dry_run=False, run_id=None):
    email  = recipient["email"]
    result = {
        "email":     email,
        "name":      (recipient.get("first_name","") + " " + recipient.get("last_name","")).strip(),
        "status":    None,
        "attempts":  0,
        "error":     "",
        "timestamp": datetime.now().isoformat(),
    }

    if dry_run:
        result["status"]   = "dry_run"
        result["attempts"] = 1
        logger.info(f"[DRY RUN] Would send to {email}")
        return result

    for attempt in range(1, max_retries + 1):
        result["attempts"] = attempt
        try:
            msg = build_message(smtp_cfg, recipient, subject_tmpl, body_tmpl, attachment_paths, run_id)
            ctx = ssl.create_default_context()
            with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=20) as server:
                server.ehlo()
                server.starttls(context=ctx)
                server.ehlo()
                server.login(smtp_cfg["user"], smtp_cfg["password"])
                server.sendmail(smtp_cfg["user"], email, msg.as_bytes())
            result["status"] = "success"
            logger.info(f"Sent to {email} (attempt {attempt})")
            return result
        except smtplib.SMTPRecipientsRefused as e:
            result["status"] = "failed"
            result["error"]  = f"Recipient refused: {e}"
            logger.error(f"Hard bounce {email}: {result['error']}")
            return result
        except smtplib.SMTPAuthenticationError:
            result["status"] = "failed"
            result["error"]  = "Authentication failed — check your email and App Password in SMTP Settings."
            logger.error(f"Auth failed for {email}")
            return result
        except Exception as e:
            result["error"] = str(e)
            logger.warning(f"Attempt {attempt} failed for {email}: {e}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)

    result["status"] = "failed"
    logger.error(f"Permanently failed {email} after {max_retries} attempts: {result['error']}")
    return result

# ── Run campaign ───────────────────────────────────────────────────────────────
def run_campaign(recipients, subject_tmpl, body_tmpl, mode="sequential", delay=0.5,
                 max_workers=10, max_retries=3, attachment_paths=None, dry_run=False,
                 progress_callback=None, smtp_override=None):

    run_id   = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    logger   = get_run_logger(run_id)
    smtp_cfg = get_smtp_config(smtp_override)

    valid, invalid = validate_recipients(recipients)
    total = len(valid)
    logger.info(f"Campaign start | run_id={run_id} | total={total} | mode={mode} | dry_run={dry_run}")

    # Log attachment info
    valid_att = [p for p in (attachment_paths or []) if p and os.path.exists(p)]
    missing   = [p for p in (attachment_paths or []) if p and not os.path.exists(p)]
    if valid_att:
        logger.info(f"Attachments ({len(valid_att)}): {[os.path.basename(p) for p in valid_att]}")
    if missing:
        logger.warning(f"Missing attachment files (skipped): {missing}")

    results = []
    lock    = threading.Lock()

    for inv in invalid:
        r = {"email": inv.get("email",""), "name": "", "status": "invalid",
             "attempts": 0, "error": inv.get("error","Invalid"), "timestamp": datetime.now().isoformat()}
        results.append(r)
        if progress_callback: progress_callback(r)

    def _send(recipient):
        res = send_one(smtp_cfg, recipient, subject_tmpl, body_tmpl,
                       valid_att, max_retries, logger, dry_run, run_id)
        with lock: results.append(res)
        if progress_callback: progress_callback(res)
        return res

    if mode == "sequential":
        for i, rec in enumerate(valid):
            _send(rec)
            if i < total - 1: time.sleep(delay)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for _ in as_completed([ex.submit(_send, r) for r in valid]):
                pass

    success   = sum(1 for r in results if r["status"] == "success")
    failed    = sum(1 for r in results if r["status"] == "failed")
    inv_count = sum(1 for r in results if r["status"] == "invalid")

    logger.info(f"Campaign complete | success={success} | failed={failed} | invalid={inv_count}")

    return {
        "run_id":      run_id,
        "total":       len(results),
        "success":     success,
        "failed":      failed,
        "invalid":     inv_count,
        "mode":        mode,
        "results":     results,
        "log_file":    f"logs/{run_id}.log",
        "report_file": save_report(run_id, results),
    }

# ── CSV report ─────────────────────────────────────────────────────────────────
def save_report(run_id, results):
    os.makedirs("logs", exist_ok=True)
    path = f"logs/{run_id}_report.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["email","name","status","attempts","error","timestamp"])
        w.writeheader(); w.writerows(results)
    return path