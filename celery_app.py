"""
celery_app.py - MailOps Phase 5  |  Celery + Redis task queue

Run the worker from the mailer/ folder:
    celery -A celery_app worker --loglevel=info --pool=solo

Run the beat scheduler (for periodic tasks):
    celery -A celery_app beat --loglevel=info

Monitor via Flower (optional):
    celery -A celery_app flower --port=5555
"""

import os, ssl, smtplib, threading
from datetime import datetime, timezone
from celery import Celery
from celery.utils.log import get_task_logger
from dotenv import load_dotenv

load_dotenv()

logger = get_task_logger(__name__)

# ── Celery app ─────────────────────────────────────────────────────────────────
def make_celery():
    broker = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    broker = broker  # used as both broker and result backend
    app    = Celery(
        "mailops",
        broker=broker,
        backend=broker,
    )
    app.conf.update(
        task_serializer        = "json",
        result_serializer      = "json",
        accept_content         = ["json"],
        timezone               = "UTC",
        enable_utc             = True,
        broker_connection_retry_on_startup = True,
        task_track_started     = True,
        task_acks_late         = True,
        worker_prefetch_multiplier = 1,
        # Scheduled task: check for due campaigns every 60 seconds
        beat_schedule          = {
            "check-scheduled-campaigns": {
                "task":     "celery_app.dispatch_due_campaigns",
                "schedule": 60.0,
            },
        },
    )
    return app

celery = make_celery()

# ── Tasks ──────────────────────────────────────────────────────────────────────
@celery.task(bind=True, max_retries=3, default_retry_delay=60, name="celery_app.send_scheduled_campaign")
def send_scheduled_campaign(self, campaign_id):
    """
    Execute a scheduled campaign by its MongoDB _id string.
    Called by dispatch_due_campaigns when the scheduled time arrives.
    """
    import store
    from mailer_engine import run_campaign
    from bson import ObjectId

    db  = store.get_db()
    doc = db.scheduled_campaigns.find_one({"_id": ObjectId(campaign_id)})

    if not doc:
        logger.error(f"Scheduled campaign {campaign_id} not found.")
        return

    if doc.get("status") != "scheduled":
        logger.info(f"Campaign {campaign_id} status={doc['status']} — skipping.")
        return

    # Mark as running
    db.scheduled_campaigns.update_one(
        {"_id": ObjectId(campaign_id)},
        {"$set": {"status": "running", "started_at": datetime.utcnow()}}
    )

    user_id  = doc["user_id"]
    run_id   = doc.get("run_id", f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
    smtp_cfg = store.get_smtp_config(user_id)

    if not smtp_cfg:
        db.scheduled_campaigns.update_one(
            {"_id": ObjectId(campaign_id)},
            {"$set": {"status": "failed", "error": "SMTP not configured"}}
        )
        return

    results   = {"success": 0, "failed": 0, "results": []}
    lock      = threading.Lock()

    def prog(r):
        with lock:
            results["results"].append(r)
            if r["status"] == "success":               results["success"] += 1
            elif r["status"] in ("failed", "invalid"): results["failed"]  += 1

    try:
        s = run_campaign(
            recipients        = doc["recipients"],
            subject_tmpl      = doc["subject"],
            body_tmpl         = doc["body"],
            mode              = doc.get("mode", "sequential"),
            delay             = doc.get("delay", 0.5),
            max_workers       = doc.get("max_workers", 10),
            max_retries       = 3,
            attachment_paths  = doc.get("attachment_paths") or None,
            dry_run           = doc.get("dry_run", False),
            progress_callback = prog,
            smtp_override     = smtp_cfg,
        )
        fin = datetime.utcnow()
        db.scheduled_campaigns.update_one(
            {"_id": ObjectId(campaign_id)},
            {"$set": {
                "status":      "complete",
                "finished_at": fin,
                "success":     s["success"],
                "failed":      s["failed"],
                "report_file": s.get("report_file"),
                "log_file":    s.get("log_file"),
            }}
        )
        # Also save to campaigns collection (shows in history)
        store.save_campaign(user_id, run_id, {
            "status":      "complete",
            "total":       doc.get("total", len(doc["recipients"])),
            "success":     s["success"],
            "failed":      s["failed"],
            "invalid":     0,
            "mode":        doc.get("mode", "sequential"),
            "started_at":  doc.get("scheduled_for").isoformat() if doc.get("scheduled_for") else fin.isoformat(),
            "finished_at": fin.isoformat(),
            "report_file": s.get("report_file"),
            "log_file":    s.get("log_file"),
        })
        # Increment daily quota counter
        if not doc.get("dry_run"):
            store.increment_daily_quota(user_id, s["success"])
        logger.info(f"Campaign {campaign_id} complete. success={s['success']} failed={s['failed']}")

    except Exception as exc:
        logger.error(f"Campaign {campaign_id} failed: {exc}")
        db.scheduled_campaigns.update_one(
            {"_id": ObjectId(campaign_id)},
            {"$set": {"status": "failed", "error": str(exc), "finished_at": datetime.utcnow()}}
        )
        raise self.retry(exc=exc)


@celery.task(name="celery_app.dispatch_due_campaigns")
def dispatch_due_campaigns():
    """
    Beat task — runs every 60 seconds.
    Finds all scheduled campaigns whose time has arrived and dispatches them.
    """
    import store
    now = datetime.utcnow()
    db  = store.get_db()
    due = list(db.scheduled_campaigns.find({
        "status":        "scheduled",
        "scheduled_for": {"$lte": now},
    }))
    logger.info(f"Beat check: {len(due)} campaign(s) due.")
    for doc in due:
        cid = str(doc["_id"])
        # Mark as queued immediately to prevent double-dispatch
        db.scheduled_campaigns.update_one(
            {"_id": doc["_id"], "status": "scheduled"},
            {"$set": {"status": "queued"}}
        )
        send_scheduled_campaign.delay(cid)
        logger.info(f"Dispatched campaign {cid}")
