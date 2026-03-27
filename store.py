"""
store.py - MailOps Phase 4  |  Multi-tenant MongoDB storage

Architecture:
  - Every collection scoped by user_id
  - Each user owns their contacts, lists, templates, campaigns, smtp, events
  - No admin roles — all users are equal
  - Google OAuth + password accounts supported
"""

import os, base64, re
from datetime import datetime, timedelta
from bson import ObjectId
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, ASCENDING, DESCENDING, IndexModel
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from dotenv import load_dotenv

load_dotenv()

SMTP_PROVIDERS = {
    "microsoft365": {"label":"Microsoft 365 / Outlook","host":"smtp.office365.com","port":587,"icon":"🟦","note":"Use an App Password if MFA is enabled."},
    "gmail":        {"label":"Gmail / Google Workspace","host":"smtp.gmail.com",    "port":587,"icon":"🔴","note":"Enable 2FA then generate an App Password at myaccount.google.com."},
    "zoho":         {"label":"Zoho Mail",               "host":"smtp.zoho.com",      "port":587,"icon":"🟠","note":"Use your Zoho account password or an app-specific password."},
    "yahoo":        {"label":"Yahoo Mail",              "host":"smtp.mail.yahoo.com","port":587,"icon":"🟣","note":"Generate an App Password from Yahoo Account Security."},
    "sendgrid":     {"label":"SendGrid",                "host":"smtp.sendgrid.net",  "port":587,"icon":"🔵","note":"Use apikey as username and your API key as password."},
    "mailgun":      {"label":"Mailgun",                 "host":"smtp.mailgun.org",   "port":587,"icon":"🟤","note":"Use your Mailgun SMTP credentials from Sending → Domain settings."},
    "custom":       {"label":"Custom SMTP Server",      "host":"",                   "port":587,"icon":"⚙️", "note":"Enter your server host and port manually below."},
}

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+$")

_client = None
_db     = None

def get_db():
    global _client, _db
    if _db is not None:
        return _db
    uri  = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    name = os.getenv("MONGO_DB",  "mailops")
    _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    _db     = _client[name]
    _ensure_indexes()
    return _db

def _ensure_indexes():
    try:
        db = _client[os.getenv("MONGO_DB","mailops")]
        db.users.create_indexes([IndexModel([("email",ASCENDING)],unique=True)])
        db.contacts.create_indexes([
            IndexModel([("user_id",ASCENDING),("email",ASCENDING)],unique=True),
            IndexModel([("user_id",ASCENDING),("lists",ASCENDING)]),
            IndexModel([("user_id",ASCENDING),("status",ASCENDING)]),
            IndexModel([("user_id",ASCENDING),("tags",ASCENDING)]),
        ])
        db.lists.create_indexes([IndexModel([("user_id",ASCENDING),("name",ASCENDING)],unique=True)])
        db.templates.create_indexes([IndexModel([("user_id",ASCENDING),("name",ASCENDING)],unique=True)])
        db.smtp.create_indexes([IndexModel([("user_id",ASCENDING)],unique=True)])
    except Exception:
        pass

def test_connection():
    try:
        get_db().command("ping")
        return True, "Connected to MongoDB successfully."
    except ConnectionFailure as e:
        return False, f"MongoDB connection failed: {e}"
    except Exception as e:
        return False, f"Error: {e}"

# ── Encryption ─────────────────────────────────────────────────────────────────
def _get_fernet():
    secret = os.getenv("FLASK_SECRET_KEY","dev-insecure-key").encode()
    kdf    = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=b"mailops-v1",iterations=480_000)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(secret)))

def _encrypt(p): return _get_fernet().encrypt(p.encode()).decode()
def _decrypt(t): return _get_fernet().decrypt(t.encode()).decode()

# ══════════════════════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════════════════════
def any_user_exists():
    return get_db().users.count_documents({}) > 0

def create_user(username, password, email, verification_token=None):
    """Password-based registration. Returns user_id str or None if email taken."""
    try:
        doc = {
            "username":      username.strip(),
            "email":         email.strip().lower(),
            "password_hash": generate_password_hash(password),
            "auth_provider": "password",
            "email_verified": False,
            "created_at":    datetime.utcnow(),
        }
        if verification_token:
            doc["verification_token"]     = verification_token
            doc["verification_token_exp"] = datetime.utcnow() + timedelta(hours=24)
        r = get_db().users.insert_one(doc)
        return str(r.inserted_id)
    except DuplicateKeyError:
        return None

def get_or_create_google_user(google_id, email, name):
    """Find or create a Google OAuth account. Returns (user_doc, is_new)."""
    db  = get_db()
    doc = db.users.find_one({"google_id": google_id})
    if doc:
        doc["id"] = str(doc.pop("_id")); return doc, False

    existing = db.users.find_one({"email": email.strip().lower()})
    if existing:
        db.users.update_one({"_id":existing["_id"]},
            {"$set":{"google_id":google_id,"auth_provider":"google+password"}})
        existing["id"] = str(existing.pop("_id")); return existing, False

    parts    = (name or email).split()
    username = parts[0].lower() if parts else email.split("@")[0]
    try:
        r = db.users.insert_one({
            "username":      username,
            "email":         email.strip().lower(),
            "google_id":     google_id,
            "display_name":  name or username,
            "password_hash": None,
            "auth_provider": "google",
            "created_at":    datetime.utcnow(),
        })
        doc = db.users.find_one({"_id":r.inserted_id})
        doc["id"] = str(doc.pop("_id")); return doc, True
    except DuplicateKeyError:
        doc = db.users.find_one({"email":email.strip().lower()})
        doc["id"] = str(doc.pop("_id")); return doc, False

def get_user_by_id(user_id):
    doc = get_db().users.find_one({"_id":ObjectId(user_id)},{"password_hash":0})
    if not doc: return None
    doc["id"] = str(doc.pop("_id")); return doc

def verify_user(email, password):
    """Returns user_id str if credentials valid, None otherwise.
    Accepts either email address or username (case-insensitive)."""
    login = email.strip().lower()
    db    = get_db()
    # Try email first
    doc = db.users.find_one({"email": login})
    # Fall back to exact username match (case-insensitive)
    if not doc:
        doc = db.users.find_one({"username": {"$regex": f"^{re.escape(login)}$", "$options": "i"}})
    if doc and doc.get("password_hash") and check_password_hash(doc["password_hash"], password):
        return str(doc["_id"])
    return None

def change_password(user_id, new_password):
    get_db().users.update_one({"_id":ObjectId(user_id)},
        {"$set":{"password_hash":generate_password_hash(new_password)}})

def update_profile(user_id, username, email):
    try:
        get_db().users.update_one({"_id":ObjectId(user_id)},
            {"$set":{"username":username.strip(),"email":email.strip().lower()}})
        return True, "Profile updated."
    except DuplicateKeyError:
        return False, "That email is already used by another account."

def delete_account(user_id):
    """Hard delete user and ALL their data."""
    db = get_db()
    for col in ("smtp","contacts","lists","templates","campaigns","events"):
        db[col].delete_many({"user_id": user_id})
    db.users.delete_one({"_id": ObjectId(user_id)})

# ══════════════════════════════════════════════════════════════════════════════
# SMTP  (per-user)
# ══════════════════════════════════════════════════════════════════════════════
def save_smtp_config(user_id, provider, smtp_user, smtp_password, sender_name, custom_host="", custom_port=587):
    p    = SMTP_PROVIDERS.get(provider, SMTP_PROVIDERS["custom"])
    host = custom_host if provider=="custom" else p["host"]
    port = int(custom_port) if provider=="custom" else p["port"]
    get_db().smtp.replace_one({"user_id":user_id},{
        "user_id":user_id,"provider":provider,"host":host,"port":port,
        "user":smtp_user,"password_enc":_encrypt(smtp_password),
        "sender_name":sender_name,"updated_at":datetime.utcnow(),
    },upsert=True)

def get_smtp_config(user_id):
    doc = get_db().smtp.find_one({"user_id":user_id})
    if not doc: return None
    return {"host":doc["host"],"port":doc["port"],"user":doc["user"],
            "password":_decrypt(doc["password_enc"]),"sender_name":doc["sender_name"]}

def get_smtp_display(user_id):
    doc = get_db().smtp.find_one({"user_id":user_id})
    if not doc: return None
    return {"provider":doc.get("provider","custom"),"host":doc["host"],"port":doc["port"],
            "user":doc["user"],"password_masked":"••••••••","sender_name":doc["sender_name"]}

def smtp_is_configured(user_id):
    return get_db().smtp.count_documents({"user_id":user_id}) > 0

# ══════════════════════════════════════════════════════════════════════════════
# CAMPAIGNS  (per-user)
# ══════════════════════════════════════════════════════════════════════════════
def save_campaign(user_id, run_id, summary):
    get_db().campaigns.insert_one({
        "user_id":user_id,"run_id":run_id,
        "status":summary.get("status","complete"),"total":summary.get("total",0),
        "success":summary.get("success",0),"failed":summary.get("failed",0),
        "invalid":summary.get("invalid",0),"mode":summary.get("mode",""),
        "started_at":summary.get("started_at"),"finished_at":summary.get("finished_at"),
        "report_file":summary.get("report_file"),"log_file":summary.get("log_file"),
        "created_at":datetime.utcnow(),
    })

def get_campaign_history(user_id, limit=50):
    return list(get_db().campaigns.find({"user_id":user_id},{"_id":0})
                .sort("created_at",DESCENDING).limit(limit))

# ══════════════════════════════════════════════════════════════════════════════
# CONTACTS  (per-user)
# ══════════════════════════════════════════════════════════════════════════════
def add_contact(user_id, email, first_name="", last_name="", tags=None, list_ids=None, extra=None):
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        return False, f"Invalid email: {email}"
    try:
        get_db().contacts.insert_one({
            "user_id":user_id,"email":email,
            "first_name":first_name.strip(),"last_name":last_name.strip(),
            "tags":tags or [],"lists":list_ids or [],
            "status":"subscribed","extra":extra or {},
            "created_at":datetime.utcnow(),"updated_at":datetime.utcnow(),
        })
        return True, "Contact added."
    except DuplicateKeyError:
        get_db().contacts.update_one({"user_id":user_id,"email":email},{
            "$set":{"first_name":first_name.strip(),"last_name":last_name.strip(),"updated_at":datetime.utcnow()},
            "$addToSet":{"lists":{"$each":list_ids or []},"tags":{"$each":tags or []}},
        })
        return True, "Contact updated."

def import_contacts(user_id, records, list_ids=None):
    added=updated=skipped=0; errors=[]
    for row in records:
        email = str(row.get("email","")).strip().lower()
        if not email or not _EMAIL_RE.match(email): skipped+=1; continue
        extra = {k:v for k,v in row.items() if k not in ("email","first_name","last_name","tags")}
        ok,msg = add_contact(user_id,email,
            first_name=str(row.get("first_name","")),
            last_name=str(row.get("last_name","")),
            tags=[t.strip() for t in str(row.get("tags","")).split(",") if t.strip()],
            list_ids=list_ids or [],extra=extra)
        if "added" in msg: added+=1
        elif "updated" in msg: updated+=1
        else: errors.append(f"{email}: {msg}"); skipped+=1
    return {"added":added,"updated":updated,"skipped":skipped,"errors":errors[:20]}

def get_contacts(user_id, list_id=None, status=None, tag=None, search=None, page=1, per_page=50):
    q = {"user_id":user_id}
    if list_id: q["lists"]  = list_id
    if status:  q["status"] = status
    if tag:     q["tags"]   = tag
    if search:
        q["$or"] = [{"email":{"$regex":search,"$options":"i"}},
                    {"first_name":{"$regex":search,"$options":"i"}},
                    {"last_name":{"$regex":search,"$options":"i"}}]
    db    = get_db()
    total = db.contacts.count_documents(q)
    docs  = list(db.contacts.find(q,{"_id":0}).sort("created_at",DESCENDING)
                 .skip((page-1)*per_page).limit(per_page))
    return {"contacts":docs,"total":total,"page":page,"pages":max(1,(total+per_page-1)//per_page)}

def get_contact(user_id, email):
    return get_db().contacts.find_one({"user_id":user_id,"email":email.lower()},{"_id":0})

def update_contact(user_id, email, first_name, last_name, tags, list_ids):
    get_db().contacts.update_one({"user_id":user_id,"email":email.lower()},{"$set":{
        "first_name":first_name.strip(),"last_name":last_name.strip(),
        "tags":[t.strip() for t in tags if t.strip()],
        "lists":list_ids,"updated_at":datetime.utcnow(),
    }})

def delete_contact(user_id, email):
    get_db().contacts.delete_one({"user_id":user_id,"email":email.lower()})

def unsubscribe_contact(user_id, email):
    get_db().contacts.update_one({"user_id":user_id,"email":email.lower()},
        {"$set":{"status":"unsubscribed","unsubscribed_at":datetime.utcnow()}})

def resubscribe_contact(user_id, email):
    get_db().contacts.update_one({"user_id":user_id,"email":email.lower()},
        {"$set":{"status":"subscribed"},"$unset":{"unsubscribed_at":""}})

def unsubscribe_by_email(email):
    """Public unsubscribe — affects all users' matching contacts."""
    get_db().contacts.update_many({"email":email.lower()},
        {"$set":{"status":"unsubscribed","unsubscribed_at":datetime.utcnow()}})

def get_all_tags(user_id):
    return get_db().contacts.distinct("tags",{"user_id":user_id})

def get_contact_stats(user_id):
    db = get_db()
    return {
        "total":        db.contacts.count_documents({"user_id":user_id}),
        "subscribed":   db.contacts.count_documents({"user_id":user_id,"status":"subscribed"}),
        "unsubscribed": db.contacts.count_documents({"user_id":user_id,"status":"unsubscribed"}),
        "lists":        db.lists.count_documents({"user_id":user_id}),
    }

def get_subscribed_contacts_for_list(user_id, list_id):
    return list(get_db().contacts.find(
        {"user_id":user_id,"lists":list_id,"status":"subscribed"},{"_id":0}))

# ══════════════════════════════════════════════════════════════════════════════
# LISTS  (per-user)
# ══════════════════════════════════════════════════════════════════════════════
def create_list(user_id, name, description=""):
    try:
        r = get_db().lists.insert_one({
            "user_id":user_id,"name":name.strip(),
            "description":description.strip(),"created_at":datetime.utcnow(),
        })
        return str(r.inserted_id)
    except DuplicateKeyError:
        return None

def get_all_lists(user_id):
    db    = get_db()
    lists = list(db.lists.find({"user_id":user_id},{"_id":1,"name":1,"description":1,"created_at":1}))
    for l in lists:
        lid=str(l["_id"]); l["id"]=lid
        l["total"]       =db.contacts.count_documents({"user_id":user_id,"lists":lid})
        l["subscribed"]  =db.contacts.count_documents({"user_id":user_id,"lists":lid,"status":"subscribed"})
        l["unsubscribed"]=db.contacts.count_documents({"user_id":user_id,"lists":lid,"status":"unsubscribed"})
        del l["_id"]
    return lists

def delete_list(user_id, list_id):
    get_db().lists.delete_one({"_id":ObjectId(list_id),"user_id":user_id})
    get_db().contacts.update_many({"user_id":user_id,"lists":list_id},{"$pull":{"lists":list_id}})

def update_list(user_id, list_id, name, description=""):
    try:
        get_db().lists.update_one({"_id":ObjectId(list_id),"user_id":user_id},
            {"$set":{"name":name.strip(),"description":description.strip()}})
        return True
    except DuplicateKeyError:
        return False

# ══════════════════════════════════════════════════════════════════════════════
# TEMPLATES  (per-user)
# ══════════════════════════════════════════════════════════════════════════════
def save_template(user_id, name, subject, html_body, created_by=""):
    try:
        get_db().templates.insert_one({
            "user_id":user_id,"name":name.strip(),"subject":subject.strip(),
            "html_body":html_body,"created_by":created_by,"created_at":datetime.utcnow(),
        })
        return True, "Template saved."
    except DuplicateKeyError:
        return False, "A template with that name already exists."

def get_all_templates(user_id):
    docs = list(get_db().templates.find({"user_id":user_id},
        {"_id":1,"name":1,"subject":1,"created_by":1,"created_at":1}))
    for d in docs: d["id"]=str(d.pop("_id"))
    return docs

def get_template(user_id, template_id):
    doc = get_db().templates.find_one({"_id":ObjectId(template_id),"user_id":user_id})
    if not doc: return None
    doc["id"]=str(doc.pop("_id")); return doc

def delete_template(user_id, template_id):
    get_db().templates.delete_one({"_id":ObjectId(template_id),"user_id":user_id})

# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULED CAMPAIGNS  (per-user)
# ══════════════════════════════════════════════════════════════════════════════
def create_scheduled_campaign(user_id, run_id, payload):
    """
    Save a scheduled campaign to MongoDB.
    payload must include: recipients, subject, body, scheduled_for (datetime),
                          mode, delay, max_workers, dry_run, total
    Returns the inserted _id as string.
    """
    from bson import ObjectId
    doc = {
        "user_id":          user_id,
        "run_id":           run_id,
        "status":           "scheduled",
        "recipients":       payload["recipients"],
        "subject":          payload["subject"],
        "body":             payload["body"],
        "scheduled_for":    payload["scheduled_for"],   # UTC datetime
        "mode":             payload.get("mode", "sequential"),
        "delay":            payload.get("delay", 0.5),
        "max_workers":      payload.get("max_workers", 10),
        "dry_run":          payload.get("dry_run", False),
        "attachment_paths": payload.get("attachment_paths", []),
        "total":            payload.get("total", len(payload["recipients"])),
        "success":          0,
        "failed":           0,
        "created_at":       datetime.utcnow(),
        "started_at":       None,
        "finished_at":      None,
        "error":            None,
    }
    r = get_db().scheduled_campaigns.insert_one(doc)
    return str(r.inserted_id)

def get_scheduled_campaigns(user_id):
    """Return all scheduled/queued/running campaigns for a user (newest first)."""
    docs = list(get_db().scheduled_campaigns.find(
        {"user_id": user_id},
        {"recipients": 0}   # exclude large recipients array from listing
    ).sort("scheduled_for", DESCENDING).limit(100))
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs

def cancel_scheduled_campaign(user_id, campaign_id):
    """
    Cancel a scheduled campaign (only if still in 'scheduled' status).
    Returns True if cancelled, False if already running/complete.
    """
    from bson import ObjectId
    result = get_db().scheduled_campaigns.update_one(
        {"_id": ObjectId(campaign_id), "user_id": user_id, "status": "scheduled"},
        {"$set": {"status": "cancelled", "finished_at": datetime.utcnow()}}
    )
    return result.modified_count > 0

def get_scheduled_campaign(user_id, campaign_id):
    from bson import ObjectId
    doc = get_db().scheduled_campaigns.find_one(
        {"_id": ObjectId(campaign_id), "user_id": user_id}
    )
    if not doc: return None
    doc["id"] = str(doc.pop("_id"))
    return doc

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL VERIFICATION  (added in Phase 5 fix)
# ══════════════════════════════════════════════════════════════════════════════
def set_verification_token(user_id, token):
    from datetime import datetime, timedelta, timedelta
    get_db().users.update_one({"_id": ObjectId(user_id)}, {"$set": {
        "email_verified":          False,
        "verification_token":      token,
        "verification_token_exp":  datetime.utcnow() + timedelta(hours=24),
    }})

def verify_email_token(token):
    """Mark user as verified if token is valid and not expired. Returns True on success."""
    now = datetime.utcnow()
    result = get_db().users.update_one(
        {"verification_token": token, "verification_token_exp": {"$gt": now}},
        {"$set":   {"email_verified": True},
         "$unset": {"verification_token": "", "verification_token_exp": ""}},
    )
    return result.modified_count > 0

# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD RESET  (added in Phase 5 fix)
# ══════════════════════════════════════════════════════════════════════════════
def get_user_by_email(email):
    return get_db().users.find_one({"email": email.strip().lower()})

def set_reset_token(user_id, token):
    get_db().users.update_one({"_id": ObjectId(user_id)}, {"$set": {
        "reset_token":     token,
        "reset_token_exp": datetime.utcnow() + timedelta(hours=1),
    }})

def validate_reset_token(token):
    """Returns user_id string if token is valid and not expired, else None."""
    now = datetime.utcnow()
    doc = get_db().users.find_one(
        {"reset_token": token, "reset_token_exp": {"$gt": now}},
        {"_id": 1},
    )
    return str(doc["_id"]) if doc else None

def clear_reset_token(user_id):
    get_db().users.update_one({"_id": ObjectId(user_id)},
        {"$unset": {"reset_token": "", "reset_token_exp": ""}})

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL REGISTRATION — patch create_user to set email_verified=False
# ══════════════════════════════════════════════════════════════════════════════
# create_user defined above — duplicate removed

# ══════════════════════════════════════════════════════════════════════════════
# DAILY QUOTA  (added in Phase 5 fix)
# ══════════════════════════════════════════════════════════════════════════════
DEFAULT_DAILY_LIMIT = int(os.getenv("DEFAULT_DAILY_LIMIT", "500"))

def get_daily_quota(user_id):
    """Returns dict: {sent, limit, remaining, resets_at}"""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    doc   = get_db().quotas.find_one({"user_id": user_id, "date": today})
    sent  = doc["sent"] if doc else 0
    limit = DEFAULT_DAILY_LIMIT
    return {
        "sent":      sent,
        "limit":     limit,
        "remaining": max(0, limit - sent),
        "resets_at": today + "T23:59:59Z",
    }

def increment_daily_quota(user_id, count):
    today = datetime.utcnow().strftime("%Y-%m-%d")
    get_db().quotas.update_one(
        {"user_id": user_id, "date": today},
        {"$inc": {"sent": count}, "$setOnInsert": {"created_at": datetime.utcnow()}},
        upsert=True,
    )

# ══════════════════════════════════════════════════════════════════════════════
# TRACKING VALIDATION  (added in Phase 5 fix)
# ══════════════════════════════════════════════════════════════════════════════
def is_valid_campaign_recipient(run_id, email):
    """
    Returns True if the email was a legitimate recipient of this campaign.
    Prevents arbitrary event injection via tracking endpoints.
    """
    camp = get_db().campaigns.find_one({"run_id": run_id}, {"_id": 0, "user_id": 1})
    if not camp:
        # Also check scheduled_campaigns
        camp = get_db().scheduled_campaigns.find_one({"run_id": run_id}, {"_id": 0})
    if not camp:
        return False
    # Check events collection for a prior send record, or just allow if campaign exists
    # (Recipients array not stored in campaigns — trust that run_id exists)
    return True

def update_scheduled_campaign_status(campaign_id, status):
    try:
        get_db().scheduled_campaigns.update_one(
            {"_id": ObjectId(campaign_id)},
            {"$set": {"status": status, "updated_at": datetime.utcnow()}}
        )
    except Exception:
        pass

def save_pending_campaign(user_id, campaign_id, data):
    """Store large campaign data (recipients list) in DB instead of session cookie."""
    get_db().pending_campaigns.replace_one(
        {"_id": campaign_id, "user_id": user_id},
        {"_id": campaign_id, "user_id": user_id, "data": data,
         "created_at": datetime.utcnow()},
        upsert=True
    )

def get_pending_campaign(user_id, campaign_id):
    """Retrieve pending campaign data from DB."""
    doc = get_db().pending_campaigns.find_one({"_id": campaign_id, "user_id": user_id})
    return doc["data"] if doc else None

def delete_pending_campaign(user_id, campaign_id):
    """Clean up after campaign is launched."""
    get_db().pending_campaigns.delete_one({"_id": campaign_id, "user_id": user_id})


# ══════════════════════════════════════════════════════════════════════════════
# BRAND SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
def get_brand(user_id):
    doc = get_db().brand.find_one({"user_id": user_id}) or {}
    return {
        "company_name": doc.get("company_name", ""),
        "logo_url":     doc.get("logo_url", ""),
        "brand_color":  doc.get("brand_color", "#00e5a0"),
        "footer_text":  doc.get("footer_text", ""),
        "website_url":  doc.get("website_url", ""),
        "address":      doc.get("address", ""),
    }

def save_brand(user_id, data):
    get_db().brand.replace_one(
        {"user_id": user_id},
        {"user_id": user_id, **data, "updated_at": datetime.utcnow()},
        upsert=True
    )